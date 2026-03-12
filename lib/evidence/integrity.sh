#!/usr/bin/env bash
# =============================================================================
# lib/evidence/integrity.sh — SHA-256 Evidence Manifest & Verification
# =============================================================================
#
# Provides cryptographic integrity guarantees for all collected evidence.
# Two complementary functions form a seal-and-verify workflow:
#
#   generate_manifest() — Called at the end of collection to hash every output
#     file and write manifest.json. This "seals" the evidence.
#
#   verify_manifest()   — Called later (possibly on a different host) to re-hash
#     all files and compare against the stored manifest, detecting any
#     post-collection tampering, corruption, or missing files.
#
# Architecture role:
#   Part of the evidence subsystem (alongside chain_of_custody.sh). Called by
#   engine_collect() and engine_triage() after all collectors finish, and by
#   engine_verify() for standalone re-verification.
#
# Hash algorithm:
#   SHA-256 via compute_sha256() from lib/core/utils.sh, which selects
#   shasum -a 256 (macOS) or sha256sum (Linux) based on platform.
#
# Self-exclusion:
#   manifest.json and audit.log are excluded from hashing because they are
#   written/modified during and after manifest generation itself.
#
# =============================================================================

# -----------------------------------------------------------------------------
# generate_manifest — Hash all evidence files and write manifest.json
#
# Parameters:
#   $1  output_dir — Root output directory containing all evidence files
#
# Outputs:
#   ${output_dir}/manifest.json with structure:
#     { generated_at, tool, version, file_count, files: [{file, sha256, size}] }
#
# Uses find to discover all regular files, sorts them for deterministic
# ordering, computes SHA-256 for each, and stores relative paths so the
# manifest is portable across directory locations.
# -----------------------------------------------------------------------------
generate_manifest() {
    local output_dir="$1"
    local manifest_file="${output_dir}/manifest.json"

    log_step "Generating evidence manifest"

    local entries=()

    # Walk all files in the output directory, sorted for deterministic order
    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        # Skip self-referential files that change after manifest generation
        [[ "$(basename "$file")" == "manifest.json" ]] && continue
        [[ "$(basename "$file")" == "audit.log" ]] && continue

        local hash rel_path fsize
        hash="$(compute_sha256 "$file")"
        # Store paths relative to output_dir for portability
        rel_path="${file#${output_dir}/}"
        fsize="$(file_size "$file" 2>/dev/null || echo 0)"

        entries+=("$(json_object \
            "$(json_kvs "file" "$rel_path")" \
            "$(json_kvs "sha256" "$hash")" \
            "$(json_kvn "size" "$fsize")"
        )")
    done < <(find "$output_dir" -type f 2>/dev/null | sort)

    # Assemble the manifest JSON document
    local manifest
    manifest="$(json_object \
        "$(json_kvs "generated_at" "$(utc_now)")" \
        "$(json_kvs "tool" "intrusion-inspector")" \
        "$(json_kvs "version" "$VERSION")" \
        "$(json_kvn "file_count" "${#entries[@]}")" \
        "$(json_kv "files" "$(json_array "${entries[@]+"${entries[@]}"}")")"
    )"

    json_write "$manifest_file" "$manifest"
    audit_log "manifest_generated" "SHA-256 manifest for ${#entries[@]} files"
    log_success "Manifest: ${#entries[@]} files hashed"
}

# -----------------------------------------------------------------------------
# verify_manifest — Re-hash evidence files and compare against manifest
#
# Parameters:
#   $1  input_dir — Directory containing manifest.json and evidence files
#
# Exit behavior:
#   - Exits 0 if all files match their recorded hashes
#   - Exits 1 if manifest is missing, any file is missing, or any hash
#     differs from the expected value
#
# Detects two types of integrity failures:
#   MISSING  — A file listed in the manifest no longer exists on disk
#   MISMATCH — A file exists but its current SHA-256 differs from the
#              hash recorded at collection time
#
# Uses jq for manifest parsing when available; falls back to grep+sed
# for environments without jq. Both paths produce pipe-delimited
# "file_path|sha256_hash" lines for uniform processing.
# -----------------------------------------------------------------------------
verify_manifest() {
    local input_dir="$1"
    local manifest_file="${input_dir}/manifest.json"

    if [[ ! -f "$manifest_file" ]]; then
        log_error "Manifest not found: ${manifest_file}"
        exit 1
    fi

    log_step "Verifying evidence integrity"

    local errors=()
    local verified=0
    local total=0

    # Extract file|hash pairs from the manifest.
    # jq path: clean extraction with proper JSON parsing.
    # grep path: flatten JSON to one line, regex-extract file+hash pairs,
    # reformat as pipe-delimited for the verification loop below.
    local pairs_data=""
    if has_cmd jq; then
        pairs_data="$(jq -r '.files[]? | "\(.file)|\(.sha256)"' "$manifest_file" 2>/dev/null || true)"
    else
        pairs_data="$(tr -d '\n' < "$manifest_file" | grep -oE '"file": "[^"]*"[^}]*"sha256": "[^"]*"' | \
            sed 's/"file": "//;s/".*"sha256": "/|/;s/"$//' 2>/dev/null || true)"
    fi

    # Verify each file against its expected hash
    while IFS='|' read -r file_path hash_expected; do
        [[ -z "$file_path" || -z "$hash_expected" ]] && continue
        total=$((total + 1))

        local full_path="${input_dir}/${file_path}"
        if [[ ! -f "$full_path" ]]; then
            errors+=("MISSING: ${file_path}")
            continue
        fi

        # Re-compute the hash and compare
        local hash_actual
        hash_actual="$(compute_sha256 "$full_path")"
        if [[ "$hash_actual" != "$hash_expected" ]]; then
            # Show truncated hashes in the error for readability
            errors+=("MISMATCH: ${file_path} (expected: ${hash_expected:0:12}... got: ${hash_actual:0:12}...)")
        else
            verified=$((verified + 1))
        fi
    done <<< "$pairs_data"

    # Report results — success requires zero errors
    if [[ ${#errors[@]} -eq 0 ]]; then
        log_success "VERIFIED: All ${verified} files match the manifest checksums"
    else
        log_fail "INTEGRITY FAILURE: ${#errors[@]} issue(s) detected"
        for err in "${errors[@]}"; do
            printf '  %b•%b %s\n' "$_CLR_RED" "$_CLR_RESET" "$err" >&2
        done
        exit 1
    fi
}
