#!/usr/bin/env bash
# =============================================================================
# IntrusionInspector — Sigma Rule Scanner Analyzer
# =============================================================================
#
# Purpose:
#   Provides basic Sigma rule matching against collected forensic artifacts.
#   Sigma is an open standard for describing log-based detection rules. This
#   scanner implements a lightweight subset of the Sigma specification,
#   focused on string-match selections, to enable community-sourced detection
#   rules without requiring the full sigmac compiler toolchain.
#
# Detection Methods:
#   - YAML-based Sigma rule parsing (title, level, detection.selection patterns)
#   - Case-insensitive grep matching of selection patterns against artifact data
#   - Support for multi-document YAML files (multiple rules per file via "---")
#   - ATT&CK tag extraction from Sigma rule "tags:" section
#
# Data Sources Examined:
#   - <output_dir>/raw/processes.json  — running process snapshots
#   - <output_dir>/raw/logs.json       — collected system/security log entries
#   - <output_dir>/raw/shell_history.json — user shell command history
#   These three sources cover the most common Sigma rule targets: process
#   creation events, log entries, and command-line activity.
#
# MITRE ATT&CK Mapping:
#   Sigma rules carry their own ATT&CK tags (e.g., "attack.t1059"). Matched
#   findings preserve the rule's severity level and propagate downstream to
#   the mitre_mapper for aggregation.
#
# Limitations:
#   - Only supports string-match selections (no regex, no field-specific matching)
#   - "condition:" logic (and/or/not) is not evaluated — any single pattern
#     match triggers the rule
#   - No log source filtering by product/service
#   These limitations are acceptable for triage; full Sigma evaluation requires
#   sigmac and a SIEM backend.
#
# Output:
#   Writes <output_dir>/analysis/sigma_scanner.json with all sigma_match findings.
# =============================================================================

# Scans collected artifacts against Sigma rules and writes results to JSON.
# Usage: analyze_sigma <output_dir> <sigma_path>
# Args:
#   output_dir - Root output directory containing raw/ and analysis/ subdirs
#   sigma_path - Path to a Sigma rule YAML file or directory of rule files
# Output:
#   Creates analysis/sigma_scanner.json with all matched findings
analyze_sigma() {
    local output_dir="$1"
    local sigma_path="$2"

    local findings=()

    # Parses a single Sigma rule YAML file, extracting metadata and detection
    # patterns, then dispatches each rule to _run_sigma_match for evaluation.
    # Usage: _parse_sigma_rule <rule_file>
    # Args:
    #   rule_file - Path to a Sigma rule YAML file (may contain multiple rules
    #               separated by "---" YAML document boundaries)
    # Design:
    #   A state-machine parser tracks whether we are inside the "detection:"
    #   block and within a "selection:" or "filter:" sub-block. List items
    #   (lines starting with "- ") within selections are treated as match
    #   patterns. This deliberately ignores the "condition:" logic for
    #   simplicity — any single pattern match triggers the rule.
    _parse_sigma_rule() {
        local rule_file="$1"

        local title="" level="" description="" product=""
        local in_detection=false
        local in_selection=false
        local selection_patterns=()
        local tags=()

        while IFS= read -r line; do
            local trimmed
            trimmed="$(echo "$line" | sed 's/^[[:space:]]*//')"

            case "$trimmed" in
                "title: "*)       title="${trimmed#title: }" ;;
                "level: "*)       level="${trimmed#level: }" ;;
                "description: "*) description="${trimmed#description: }" ;;
                "product: "*)     product="${trimmed#product: }" ;;
                # "detection:" marks the start of the detection block
                "detection:")     in_detection=true ;;
                # "tags:" ends the detection block (Sigma spec ordering)
                "tags:")          in_detection=false ;;
                "---")
                    # Multi-document YAML boundary — flush the current rule before
                    # resetting state for the next rule in the same file
                    if [[ -n "$title" && ${#selection_patterns[@]} -gt 0 ]]; then
                        _run_sigma_match "$title" "$level" "$description" "${selection_patterns[@]}"
                    fi
                    title="" level="" description="" product=""
                    in_detection=false in_selection=false
                    selection_patterns=()
                    ;;
                *)
                    if [[ "$in_detection" == "true" ]]; then
                        # "selection" and "filter" are Sigma detection sub-keys
                        if [[ "$trimmed" =~ ^selection|^filter ]]; then
                            in_selection=true
                        elif [[ "$trimmed" =~ ^condition ]]; then
                            # Stop collecting patterns once we hit the condition line
                            in_selection=false
                        elif [[ "$in_selection" == "true" && "$trimmed" =~ ^-\ \" ]]; then
                            # Quoted list item (e.g., - "powershell.exe")
                            local pattern="${trimmed#- }"
                            pattern="${pattern//\"/}"
                            pattern="$(echo "$pattern" | sed 's/^[[:space:]]*//')"
                            [[ -n "$pattern" ]] && selection_patterns+=("$pattern")
                        elif [[ "$in_selection" == "true" && "$trimmed" =~ ^- ]]; then
                            # Unquoted list item (e.g., - cmd.exe)
                            local pattern="${trimmed#- }"
                            pattern="${pattern//\"/}"
                            [[ -n "$pattern" ]] && selection_patterns+=("$pattern")
                        fi
                    fi
                    # Collect ATT&CK tags regardless of detection block state
                    if [[ "$trimmed" =~ ^-\ attack\. ]]; then
                        tags+=("${trimmed#- }")
                    fi
                    ;;
            esac
        done < "$rule_file"

        # Flush the final rule — no trailing "---" to trigger it in the loop
        if [[ -n "$title" && ${#selection_patterns[@]} -gt 0 ]]; then
            _run_sigma_match "$title" "$level" "$description" "${selection_patterns[@]}"
        fi
    }

    # Evaluates a parsed Sigma rule's selection patterns against the three
    # primary artifact files (processes, logs, shell history).
    # Usage: _run_sigma_match <title> <level> <desc> <pattern1> [pattern2...]
    # Args:
    #   title    - Sigma rule title for the finding report
    #   level    - Sigma severity level (informational/low/medium/high/critical)
    #   desc     - Sigma rule description
    #   patterns - One or more selection patterns to search for
    # Design:
    #   Uses case-insensitive grep (-qi) because Sigma pattern matching is
    #   case-insensitive by default. Breaks after the first matching pattern
    #   per data source to avoid duplicate findings for the same rule+source
    #   combination. Each source is checked independently so one rule can
    #   produce up to 3 findings (one per data source) if matched everywhere.
    _run_sigma_match() {
        local title="$1" level="$2" desc="$3"
        shift 3
        local patterns=("$@")

        for raw_file in "${output_dir}/raw/processes.json" "${output_dir}/raw/logs.json" "${output_dir}/raw/shell_history.json"; do
            [[ -f "$raw_file" ]] || continue
            local source
            source="$(basename "$raw_file" .json)"

            for pattern in "${patterns[@]}"; do
                if grep -qi "$pattern" "$raw_file" 2>/dev/null; then
                    findings+=("$(json_object \
                        "$(json_kvs "type" "sigma_match")" \
                        "$(json_kvs "rule_title" "$title")" \
                        "$(json_kvs "severity" "${level:-medium}")" \
                        "$(json_kvs "description" "$desc")" \
                        "$(json_kvs "matched_pattern" "$pattern")" \
                        "$(json_kvs "source" "$source")"
                    )")
                    # Break on first match to avoid duplicate findings per source
                    break
                fi
            done
        done
    }

    # Iterate over Sigma rule files. Supports both a directory of YAML files
    # and a single file path, matching the same pattern as the IOC scanner
    # for a consistent user experience.
    if [[ -d "$sigma_path" ]]; then
        for rule_file in "$sigma_path"/*.yml "$sigma_path"/*.yaml; do
            [[ -f "$rule_file" ]] || continue
            _parse_sigma_rule "$rule_file"
        done
    elif [[ -f "$sigma_path" ]]; then
        _parse_sigma_rule "$sigma_path"
    fi

    # Build the final JSON result and write to the analysis directory.
    # The "${findings[@]+"${findings[@]}"}" pattern prevents "unbound variable"
    # errors under set -u when the findings array is empty.
    local result
    result="$(json_object \
        "$(json_kvs "analyzer" "sigma_scanner")" \
        "$(json_kvn "finding_count" "${#findings[@]}")" \
        "$(json_kv "findings" "$(json_array "${findings[@]+"${findings[@]}"}")")"
    )"

    json_write "${output_dir}/analysis/sigma_scanner.json" "$result"
    log_info "Sigma scanner: ${#findings[@]} findings"
}
