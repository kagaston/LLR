#!/usr/bin/env bash
# ============================================================================
# Collector: filesystem
# ============================================================================
#
# Purpose:
#   Scans temporary directories and user download folders for suspicious or
#   recently modified files. Attackers frequently stage payloads, tools, and
#   exfiltration archives in temp dirs and Downloads because these locations
#   are writable, often overlooked, and sometimes excluded from AV scans.
#
# Artifacts gathered:
#   Per file: filename, full path, size in bytes, modification time (ISO 8601),
#   permissions string, and optional SHA-256 hash (when PROFILE_HASH_FILES
#   is enabled in the active profile).
#
# Platform support:
#   Linux:
#     - Scans TEMP_DIRS_LINUX (e.g., /tmp, /var/tmp, /dev/shm)
#     - User ~/Downloads directories
#   macOS:
#     - Scans TEMP_DIRS_MACOS (e.g., /tmp, /private/tmp, /private/var/tmp)
#     - User ~/Downloads and ~/Library/Recent directories
#     - file_size, file_perms, file_mtime use stat with macOS-specific flags
#
# Scan limits:
#   - find -maxdepth is controlled by TEMP_DIR_SCAN_DEPTH (profile-configurable)
#   - Results are capped at 500 files per directory via head to prevent
#     runaway collection on systems with massive temp directories
#   - SHA-256 hashing is opt-in via PROFILE_HASH_FILES to avoid I/O-intensive
#     hashing on systems with many large files
#
# Output:
#   JSON array of file artifacts, written via write_collector_result.
# ============================================================================

# collect_filesystem — scans temp and download dirs for file artifacts
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   The scan directory lists differ by platform (TEMP_DIRS_LINUX vs
#   TEMP_DIRS_MACOS), and macOS additionally scans ~/Library/Recent.
#   File metadata functions (file_size, file_perms, file_mtime) abstract
#   away the platform-specific stat syntax differences.
#
# Performance considerations:
#   - find with -maxdepth and head -500 caps both directory depth and file
#     count to prevent slow scans on systems with deep or bloated temp trees
#   - SHA-256 hashing is the most expensive operation and is disabled by
#     default; the profile must explicitly enable PROFILE_HASH_FILES
collect_filesystem() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()
    local scan_dirs=()

    # Select platform-appropriate temp directory list
    if is_linux; then
        scan_dirs=("${TEMP_DIRS_LINUX[@]}")
    elif is_darwin; then
        scan_dirs=("${TEMP_DIRS_MACOS[@]}")
    fi

    # Append user download directories (and macOS Recent folder) to the scan list
    while IFS= read -r home_dir; do
        [[ -d "${home_dir}/Downloads" ]] && scan_dirs+=("${home_dir}/Downloads")
        if is_darwin && [[ -d "${home_dir}/Library/Recent" ]]; then
            scan_dirs+=("${home_dir}/Library/Recent")
        fi
    done < <(get_user_homes)

    for scan_dir in "${scan_dirs[@]}"; do
        [[ -d "$scan_dir" ]] || continue

        # find is capped at TEMP_DIR_SCAN_DEPTH levels and 500 files to
        # bound collection time on systems with large temp hierarchies
        while IFS= read -r file_path; do
            [[ -f "$file_path" ]] || continue

            local fname fsize fperms mtime_epoch mtime_iso
            fname="$(basename "$file_path")"
            fsize="$(file_size "$file_path" 2>/dev/null || echo 0)"
            fperms="$(file_perms "$file_path" 2>/dev/null || echo "000")"
            mtime_epoch="$(file_mtime "$file_path" 2>/dev/null || echo 0)"
            mtime_iso="$(epoch_to_iso "$mtime_epoch" 2>/dev/null || echo "")"

            # SHA-256 hashing is opt-in because it requires reading every file's
            # full contents; on systems with large temp files this can take minutes
            local hash_val=""
            if [[ "${PROFILE_HASH_FILES:-false}" == "true" ]]; then
                hash_val="$(hash_file "$file_path" 2>/dev/null || echo "")"
            fi

            artifacts+=("$(json_object \
                "$(json_kvs "name" "$fname")" \
                "$(json_kvs "path" "$file_path")" \
                "$(json_kvn "size" "$fsize")" \
                "$(json_kvs "modified" "$mtime_iso")" \
                "$(json_kvs "permissions" "$fperms")" \
                "$(json_kvs "sha256" "$hash_val")"
            )")
        done < <(find "$scan_dir" -maxdepth "$TEMP_DIR_SCAN_DEPTH" -type f 2>/dev/null | head -500)
    done

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "filesystem" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "filesystem" "$result"
}
