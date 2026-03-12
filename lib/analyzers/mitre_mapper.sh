#!/usr/bin/env bash
# =============================================================================
# IntrusionInspector — MITRE ATT&CK Mapper Analyzer
# =============================================================================
#
# Purpose:
#   Aggregates MITRE ATT&CK technique IDs from ALL other analyzer outputs,
#   deduplicates them, maps techniques to tactics, computes a composite risk
#   score, and generates an ATT&CK Navigator layer file. This is the final
#   analyzer in the pipeline and provides the highest-level summary of the
#   investigation.
#
# Detection Methods:
#   - Technique ID extraction via grep from all analysis JSON files
#   - Technique-to-tactic mapping via a built-in lookup table
#   - Severity-weighted risk scoring (each finding's severity contributes a
#     weighted value to the cumulative score, capped at MAX_RISK_SCORE)
#   - ATT&CK Navigator layer generation for visual attack surface mapping
#
# Data Sources Examined:
#   - All files matching <output_dir>/analysis/*.json EXCEPT:
#     - mitre_attack_summary.json (this analyzer's own output, to avoid loops)
#     - timeline.json (contains no technique IDs)
#
# MITRE ATT&CK Mapping:
#   This IS the ATT&CK mapper — it covers the following technique-to-tactic
#   mappings (non-exhaustive):
#     Execution:           T1059, T1204, T1047
#     Persistence:         T1053, T1543, T1547, T1505
#     Defense Evasion:     T1055, T1036, T1027, T1218, T1216, T1553, T1562, T1014
#     Credential Access:   T1003, T1555, T1115
#     Command & Control:   T1071, T1105, T1090
#     Privilege Escalation: T1574
#
# Compatibility:
#   Uses temp files and sort/uniq pipelines instead of bash associative arrays
#   for compatibility with bash 3.x (macOS ships bash 3.2 due to GPLv3).
#
# Output:
#   - <output_dir>/analysis/mitre_attack_summary.json — technique counts,
#     tactic summary, and risk score
#   - <output_dir>/attack_navigator_layer.json — ATT&CK Navigator v4.4
#     compatible layer for import into https://mitre-attack.github.io/attack-navigator/
# =============================================================================

# Aggregates MITRE ATT&CK findings and generates summary + Navigator layer.
# Usage: analyze_mitre <output_dir>
# Args:
#   output_dir - Root output directory containing raw/ and analysis/ subdirs
# Output:
#   Creates analysis/mitre_attack_summary.json and attack_navigator_layer.json
analyze_mitre() {
    local output_dir="$1"

    # Maps a MITRE ATT&CK technique ID to its primary tactic category.
    # Usage: _technique_to_tactic <technique_id>
    # Args:
    #   tid - MITRE ATT&CK technique ID (e.g., T1059, T1059.001)
    # Returns:
    #   Prints the tactic name to stdout (e.g., "execution", "persistence")
    # Design:
    #   Uses glob patterns (T1059*) to match both base techniques and
    #   sub-techniques (e.g., T1059.001) with a single case arm. Only the
    #   PRIMARY tactic is returned even though some techniques span multiple
    #   tactics in the ATT&CK matrix — this simplification keeps the mapping
    #   table maintainable and is sufficient for triage-level reporting.
    _technique_to_tactic() {
        local tid="$1"
        case "$tid" in
            T1059*|T1204*|T1047*) echo "execution" ;;
            T1053*|T1543*|T1547*) echo "persistence" ;;
            T1055*|T1036*|T1027*|T1218*|T1216*|T1553*|T1562*) echo "defense_evasion" ;;
            T1003*|T1555*|T1115*) echo "credential_access" ;;
            T1071*|T1105*|T1090*) echo "command_and_control" ;;
            T1574*) echo "privilege_escalation" ;;
            T1014*) echo "defense_evasion" ;;
            T1505*) echo "persistence" ;;
            *) echo "unknown" ;;
        esac
    }

    # Phase 1: Harvest technique IDs and severities from all analyzer outputs.
    # Temp files are used instead of associative arrays for bash 3.x compatibility
    # (macOS ships bash 3.2). The RETURN trap ensures cleanup even if the function
    # exits early due to an error.
    local tmp_techniques
    tmp_techniques="$(mktemp)"
    local tmp_severities
    tmp_severities="$(mktemp)"
    trap "rm -f '$tmp_techniques' '$tmp_severities'" RETURN

    for analysis_file in "${output_dir}/analysis"/*.json; do
        [[ -f "$analysis_file" ]] || continue
        # Skip our own output to prevent self-referential loops on re-runs
        [[ "$(basename "$analysis_file")" == "mitre_attack_summary.json" ]] && continue
        # Skip timeline — it contains timestamps, not technique mappings
        [[ "$(basename "$analysis_file")" == "timeline.json" ]] && continue

        # Extract raw technique IDs and severity values via grep+sed.
        # This is faster than JSON parsing and works because our JSON output
        # uses a consistent, non-nested format for these fields.
        grep -o '"mitre_technique": "[^"]*"' "$analysis_file" 2>/dev/null \
            | sed 's/.*": "//;s/"//' >> "$tmp_techniques"

        grep -o '"severity": "[^"]*"' "$analysis_file" 2>/dev/null \
            | sed 's/.*": "//;s/"//' >> "$tmp_severities"
    done

    # Phase 2: Deduplicate techniques and count occurrences.
    # sort | uniq -c | sort -rn produces "count technique_id" lines sorted by
    # frequency (most common first). Two parallel arrays are built:
    #   - techniques:     for the summary report (includes tactic mapping)
    #   - nav_techniques: for the ATT&CK Navigator layer (uses Navigator schema)
    local techniques=()
    local nav_techniques=()
    local technique_count=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local count tid
        count="$(echo "$line" | awk '{print $1}')"
        tid="$(echo "$line" | awk '{print $2}')"
        [[ -z "$tid" || "$tid" == "null" ]] && continue

        local tactic
        tactic="$(_technique_to_tactic "$tid")"

        techniques+=("$(json_object \
            "$(json_kvs "technique_id" "$tid")" \
            "$(json_kvs "tactic" "$tactic")" \
            "$(json_kvn "count" "$count")"
        )")

        # Navigator layer uses "techniqueID" (camelCase) and "score" per the
        # ATT&CK Navigator JSON schema. Color #ff6666 (red) highlights all
        # detected techniques uniformly.
        nav_techniques+=("$(json_object \
            "$(json_kvs "techniqueID" "$tid")" \
            "$(json_kvn "score" "$count")" \
            "$(json_kvs "color" "#ff6666")"
        )")

        technique_count=$((technique_count + 1))
    done < <(sort "$tmp_techniques" | uniq -c | sort -rn)

    # Phase 3: Build tactic-level summary by mapping each technique to its tactic,
    # then counting how many findings fall into each tactic category.
    # This uses an intermediate temp file because the `while | while` pipeline
    # runs in a subshell, and bash arrays assigned in subshells are lost when
    # the subshell exits. Writing to a temp file and reading back is the
    # standard bash 3.x workaround for this subshell scoping limitation.
    local tactic_summary=()
    local tmp_tactics
    tmp_tactics="$(mktemp)"
    trap "rm -f '$tmp_techniques' '$tmp_severities' '$tmp_tactics'" RETURN

    while IFS= read -r tid; do
        [[ -z "$tid" || "$tid" == "null" ]] && continue
        _technique_to_tactic "$tid"
    done < "$tmp_techniques" | sort | uniq -c | sort -rn | while IFS= read -r line; do
        local count tactic
        count="$(echo "$line" | awk '{print $1}')"
        tactic="$(echo "$line" | awk '{print $2}')"
        [[ -z "$tactic" ]] && continue
        echo "$(json_object \
            "$(json_kvs "tactic" "$tactic")" \
            "$(json_kvn "count" "$count")"
        )"
    done > "$tmp_tactics"

    # Read tactic summary back from temp file into the array
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        tactic_summary+=("$entry")
    done < "$tmp_tactics"

    # Phase 4: Compute composite risk score.
    # Each finding's severity contributes a weighted value (via _severity_weight,
    # defined in the shared utilities). The score accumulates additively across
    # all findings and is capped at MAX_RISK_SCORE to produce a bounded 0-100
    # (or similar) scale. This gives analysts a single at-a-glance metric for
    # the overall severity of the investigation.
    local total_score=0
    while IFS= read -r sev; do
        [[ -z "$sev" ]] && continue
        local weight
        weight="$(_severity_weight "$sev")"
        total_score=$(( total_score + weight ))
    done < "$tmp_severities"

    [[ "$total_score" -gt "$MAX_RISK_SCORE" ]] && total_score="$MAX_RISK_SCORE"

    # Phase 5: Write the MITRE ATT&CK summary report.
    local result
    result="$(json_object \
        "$(json_kvn "risk_score" "$total_score")" \
        "$(json_kvn "max_score" "$MAX_RISK_SCORE")" \
        "$(json_kvn "technique_count" "$technique_count")" \
        "$(json_kv "techniques" "$(json_array "${techniques[@]+"${techniques[@]}"}")")" \
        "$(json_kv "tactic_summary" "$(json_array "${tactic_summary[@]+"${tactic_summary[@]}"}")")"
    )"

    json_write "${output_dir}/analysis/mitre_attack_summary.json" "$result"
    log_info "MITRE mapper: ${technique_count} techniques, risk score: ${total_score}/${MAX_RISK_SCORE}"

    # Phase 6: Generate ATT&CK Navigator layer.
    # This JSON file conforms to the Navigator v4.4 layer schema and can be
    # imported directly into the MITRE ATT&CK Navigator web app at
    # https://mitre-attack.github.io/attack-navigator/ to visualize which
    # techniques were observed. The "score" field drives the heat map intensity,
    # giving analysts an immediate visual of attack coverage.
    local nav_layer
    nav_layer="$(json_object \
        "$(json_kvs "name" "IntrusionInspector Findings")" \
        "$(json_kvs "version" "4.4")" \
        "$(json_kvs "domain" "enterprise-attack")" \
        "$(json_kv "techniques" "$(json_array "${nav_techniques[@]+"${nav_techniques[@]}"}")")"
    )"

    json_write "${output_dir}/attack_navigator_layer.json" "$nav_layer"

    # Explicit cleanup (also handled by RETURN trap, but belt-and-suspenders)
    rm -f "$tmp_techniques" "$tmp_severities" "$tmp_tactics"
}
