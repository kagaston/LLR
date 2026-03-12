#!/usr/bin/env bash
# ============================================================================
# Collector: installed_software
# ============================================================================
#
# Purpose:
#   Enumerates all installed software packages across multiple package
#   managers. Installed software data helps identify unauthorized tools,
#   vulnerable package versions, attacker-installed utilities (netcat, nmap,
#   etc.), and establishes a software inventory for the compromised system.
#
# Artifacts gathered:
#   Per package: source package manager, name, version, and manager-specific
#   metadata (architecture, description, release, application ID, path).
#
# Platform support:
#   Linux (covers all major package formats):
#     - dpkg: Debian/Ubuntu .deb packages (dpkg -l)
#     - rpm: RHEL/CentOS/Fedora .rpm packages (rpm -qa)
#     - snap: Snap packages (snap list)
#     - flatpak: Flatpak applications (flatpak list)
#   macOS:
#     - system_profiler SPApplicationsDataType: native macOS applications
#       (parsed with jq if available, raw JSON fallback otherwise)
#     - Homebrew: brew packages (brew list --versions)
#
# Performance optimization:
#   This collector writes JSON directly to a file and uses awk for bulk
#   JSON generation on all package manager outputs. Package lists can
#   contain thousands of entries (dpkg on Ubuntu typically has 1000-3000
#   packages), making the awk approach essential:
#     - awk processes the entire package listing in a single pass
#     - Avoids per-package subshell spawns for json_object/json_kvs
#     - Avoids O(n^2) bash string concatenation
#   On macOS, system_profiler JSON output is parsed with jq for structured
#   extraction, or embedded raw if jq is unavailable (avoids expensive
#   json_escape on the large system_profiler blob).
#
# Output:
#   Writes directly to raw/installed_software.json in the output directory.
#   Uses jq for pretty-printing if available.
# ============================================================================

# collect_installed_software — enumerates packages from all package managers
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Each package manager is checked with has_cmd before enumeration, so
#   the collector gracefully handles systems where only some managers are
#   installed. On Linux, dpkg and rpm are mutually exclusive on most systems,
#   but both are checked for mixed environments.
#
# File I/O strategy:
#   Uses the same direct-to-file pattern as logs and usb_devices collectors.
#   Each package manager's awk output is appended to a temp file with comma
#   separation, and the final JSON envelope is assembled around it.
collect_installed_software() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local raw_dir="${output_dir}/raw"
    ensure_dir "$raw_dir"
    local out_file="${raw_dir}/installed_software.json"
    local tmp_file
    tmp_file="$(mktemp)"
    local artifact_count=0

    if is_linux; then
        # ── dpkg (Debian/Ubuntu) ──
        # awk processes the entire dpkg -l output in one pass.
        # tail -n +6 skips dpkg's header/separator lines.
        # Only lines starting with "ii" (installed) are collected;
        # "rc" (removed but config remains) and other states are skipped.
        if has_cmd dpkg; then
            local dpkg_json
            dpkg_json="$(dpkg -l 2>/dev/null | tail -n +6 | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            /^ii/ {
                name=$2; ver=$3; arch=$4
                desc=""
                for(i=5;i<=NF;i++) desc = desc (i>5?" ":"") $i
                if (count++) printf ", "
                printf "{\"source\": \"dpkg\", \"name\": \"%s\", \"version\": \"%s\", \"architecture\": \"%s\", \"description\": \"%s\"}", \
                    esc(name), esc(ver), esc(arch), esc(desc)
            }
            END { }
            ')"
            if [[ -n "$dpkg_json" ]]; then
                [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
                printf '%s' "$dpkg_json" >> "$tmp_file"
                artifact_count=$((artifact_count + 1))
            fi
        fi

        # ── rpm (RHEL/CentOS/Fedora) ──
        # Uses a custom query format with pipe delimiters for reliable parsing.
        # awk splits on '|' to extract name, version, and release fields.
        if has_cmd rpm; then
            local rpm_json
            rpm_json="$(rpm -qa --qf '%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}\n' 2>/dev/null | awk -F'|' '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            NF >= 3 {
                if (count++) printf ", "
                printf "{\"source\": \"rpm\", \"name\": \"%s\", \"version\": \"%s\", \"release\": \"%s\"}", \
                    esc($1), esc($2), esc($3)
            }
            ')"
            if [[ -n "$rpm_json" ]]; then
                [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
                printf '%s' "$rpm_json" >> "$tmp_file"
                artifact_count=$((artifact_count + 1))
            fi
        fi

        # ── snap ──
        # snap list output has a header row (skipped by tail -n +2) followed
        # by space-delimited columns: Name, Version, Rev, Tracking, Publisher, Notes
        if has_cmd snap; then
            local snap_json
            snap_json="$(snap list 2>/dev/null | tail -n +2 | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            {
                if (count++) printf ", "
                printf "{\"source\": \"snap\", \"name\": \"%s\", \"version\": \"%s\"}", esc($1), esc($2)
            }
            ')"
            if [[ -n "$snap_json" ]]; then
                [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
                printf '%s' "$snap_json" >> "$tmp_file"
                artifact_count=$((artifact_count + 1))
            fi
        fi

        # ── flatpak ──
        # Tab-delimited columns specified explicitly to ensure consistent parsing
        if has_cmd flatpak; then
            local fp_json
            fp_json="$(flatpak list --columns=name,application,version 2>/dev/null | awk -F'\t' '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            NF >= 1 {
                if (count++) printf ", "
                printf "{\"source\": \"flatpak\", \"name\": \"%s\", \"application_id\": \"%s\", \"version\": \"%s\"}", \
                    esc($1), esc($2), esc($3)
            }
            ')"
            if [[ -n "$fp_json" ]]; then
                [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
                printf '%s' "$fp_json" >> "$tmp_file"
                artifact_count=$((artifact_count + 1))
            fi
        fi

    elif is_darwin; then
        # ── system_profiler (macOS native applications) ──
        # system_profiler outputs a large JSON blob of all installed apps.
        # If jq is available, extract structured fields (name, version, path,
        # obtained_from) for efficient downstream processing.
        # If jq is unavailable, embed the raw JSON directly — this avoids
        # the expensive json_escape call on the large system_profiler output.
        if has_cmd system_profiler; then
            local apps_json
            apps_json="$(system_profiler SPApplicationsDataType -json 2>/dev/null || true)"
            if [[ -n "$apps_json" ]]; then
                if has_cmd jq; then
                    local parsed
                    parsed="$(echo "$apps_json" | jq -r '[.SPApplicationsDataType[]? | {source: "system_profiler", name: ._name, version: .version, path: .path, obtained_from: .obtained_from}]' 2>/dev/null | sed 's/^\[//;s/\]$//')"
                    if [[ -n "$parsed" ]]; then
                        [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
                        printf '%s' "$parsed" >> "$tmp_file"
                        artifact_count=$((artifact_count + 1))
                    fi
                else
                    [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
                    printf '{"source": "system_profiler", "raw": %s}' "$apps_json" >> "$tmp_file"
                    artifact_count=$((artifact_count + 1))
                fi
            fi
        fi

        # ── Homebrew ──
        # brew list --versions outputs "package_name version1 version2 ..."
        # awk captures the first two fields (name and latest version)
        if has_cmd brew; then
            local brew_json
            brew_json="$(brew list --versions 2>/dev/null | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            {
                if (count++) printf ", "
                printf "{\"source\": \"brew\", \"name\": \"%s\", \"version\": \"%s\"}", esc($1), esc($2)
            }
            ')"
            if [[ -n "$brew_json" ]]; then
                [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
                printf '%s' "$brew_json" >> "$tmp_file"
                artifact_count=$((artifact_count + 1))
            fi
        fi
    fi

    local end_ts
    end_ts="$(epoch_now)"
    local duration=$(( end_ts - start_ts ))

    # Assemble final JSON envelope around the accumulated package artifacts
    printf '{"collector_name": "installed_software", "platform": "%s", "hostname": "%s", "collected_at": "%s", "duration_seconds": %d, "artifact_count": %d, "artifacts": [' \
        "$PLATFORM_LOWER" "$(hostname)" "$(utc_now)" "$duration" "$artifact_count" > "$out_file"
    cat "$tmp_file" >> "$out_file"
    printf ']}\n' >> "$out_file"

    rm -f "$tmp_file"

    if has_cmd jq; then
        local pretty
        pretty="$(jq '.' "$out_file" 2>/dev/null)" && printf '%s\n' "$pretty" > "$out_file"
    fi

    audit_log "collector_complete" "Collector installed_software finished"
}
