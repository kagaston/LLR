#!/usr/bin/env bash
# =============================================================================
# IntrusionInspector — YARA Scanner Analyzer
# =============================================================================
#
# Purpose:
#   Provides YARA-based pattern matching against collected forensic artifacts
#   by shelling out to the system's `yara` CLI. YARA is the industry standard
#   for malware classification and can match binary patterns, strings, and
#   complex conditions that go far beyond what grep-based scanning can detect.
#
# Detection Methods:
#   - Binary and string pattern matching via compiled YARA rules
#   - Multi-rule scanning: each .yar/.yara file is applied to every raw artifact
#   - Full YARA condition logic (hex patterns, regex, file size, entropy, etc.)
#
# Data Sources Examined:
#   - All files matching <output_dir>/raw/*.json
#   YARA scans the raw JSON content byte-by-byte, which means it can detect
#   base64-encoded payloads, hex-encoded shellcode, and embedded binary data
#   within the JSON collector output.
#
# MITRE ATT&CK Mapping:
#   YARA rules themselves typically map to specific malware families or attack
#   tools rather than ATT&CK techniques. All YARA matches are reported at
#   "high" severity because YARA rules are high-fidelity signatures — they
#   rarely produce false positives when well-written.
#
# Dependencies:
#   - Optional: `yara` CLI must be installed and in PATH. If not found, the
#     analyzer gracefully skips with a warning rather than failing. This keeps
#     IntrusionInspector functional in minimal environments.
#
# Output:
#   Writes <output_dir>/analysis/yara_scanner.json with all yara_match findings,
#   or a "skipped" status if YARA is not installed.
# =============================================================================

# Runs YARA rules against collected artifacts and writes results to JSON.
# Usage: analyze_yara <output_dir> <yara_path>
# Args:
#   output_dir - Root output directory containing raw/ and analysis/ subdirs
#   yara_path  - Path to a .yar/.yara file or directory of YARA rule files
# Output:
#   Creates analysis/yara_scanner.json with matches or skipped status
analyze_yara() {
    local output_dir="$1"
    local yara_path="$2"

    local findings=()

    # Guard: gracefully skip if YARA is not installed. Unlike other analyzers,
    # YARA is an optional external dependency. Writing a "skipped" result
    # ensures downstream consumers (mitre_mapper, report generator) know this
    # analyzer ran but had nothing to contribute, rather than assuming zero findings.
    if ! has_cmd yara; then
        log_warn "yara command not found — skipping YARA scanning"
        local result
        result="$(json_object \
            "$(json_kvs "analyzer" "yara_scanner")" \
            "$(json_kvs "status" "skipped")" \
            "$(json_kvs "reason" "yara not installed")" \
            "$(json_kvn "finding_count" 0)" \
            "$(json_kv "findings" "[]")"
        )"
        json_write "${output_dir}/analysis/yara_scanner.json" "$result"
        return 0
    fi

    # Discover YARA rule files. Both .yar and .yara extensions are accepted
    # to accommodate different community conventions. Supports a single file
    # or a directory of rule files.
    local rule_files=()
    if [[ -d "$yara_path" ]]; then
        for yf in "$yara_path"/*.yar "$yara_path"/*.yara; do
            [[ -f "$yf" ]] && rule_files+=("$yf")
        done
    elif [[ -f "$yara_path" ]]; then
        rule_files+=("$yara_path")
    fi

    # Early return if no rules were found — nothing to scan against
    if [[ ${#rule_files[@]} -eq 0 ]]; then
        log_warn "No YARA rules found in ${yara_path}"
        local result
        result="$(json_object \
            "$(json_kvs "analyzer" "yara_scanner")" \
            "$(json_kvn "finding_count" 0)" \
            "$(json_kv "findings" "[]")"
        )"
        json_write "${output_dir}/analysis/yara_scanner.json" "$result"
        return 0
    fi

    # Run each YARA rule file against every raw collector output.
    # This is an O(rules × files) scan, which is acceptable because both sets
    # are typically small (a handful of rule files, ~10-15 raw JSON files).
    # The `|| true` suppresses YARA exit codes for rules with syntax errors
    # or files that don't match, preventing set -e from aborting the scan.
    for rule_file in "${rule_files[@]}"; do
        for raw_file in "${output_dir}/raw"/*.json; do
            [[ -f "$raw_file" ]] || continue
            local source
            source="$(basename "$raw_file" .json)"

            # YARA stdout format is: "RULE_NAME FILE_PATH"
            # Parse the rule name from the first whitespace-delimited field
            while IFS= read -r match_line; do
                [[ -z "$match_line" ]] && continue
                local rule_name
                rule_name="$(echo "$match_line" | awk '{print $1}')"
                findings+=("$(json_object \
                    "$(json_kvs "type" "yara_match")" \
                    "$(json_kvs "rule_name" "$rule_name")" \
                    "$(json_kvs "rule_file" "$(basename "$rule_file")")" \
                    "$(json_kvs "source" "$source")" \
                    "$(json_kvs "severity" "high")" \
                    "$(json_kvs "raw" "$match_line")"
                )")
            done < <(yara "$rule_file" "$raw_file" 2>/dev/null || true)
        done
    done

    # Build the final JSON result and write to the analysis directory.
    # The "${findings[@]+"${findings[@]}"}" pattern prevents "unbound variable"
    # errors under set -u when the findings array is empty.
    local result
    result="$(json_object \
        "$(json_kvs "analyzer" "yara_scanner")" \
        "$(json_kvn "finding_count" "${#findings[@]}")" \
        "$(json_kv "findings" "$(json_array "${findings[@]+"${findings[@]}"}")")"
    )"

    json_write "${output_dir}/analysis/yara_scanner.json" "$result"
    log_info "YARA scanner: ${#findings[@]} findings"
}
