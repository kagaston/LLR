#!/usr/bin/env bash
# =============================================================================
# IntrusionInspector — IOC Scanner Analyzer
# =============================================================================
#
# Purpose:
#   Matches collected forensic artifacts against user-supplied Indicator of
#   Compromise (IOC) rules defined in YAML format. This is the primary
#   signature-based detection engine in IntrusionInspector, complementing the
#   heuristic-based anomaly_detector.
#
# Detection Methods:
#   - String matching of SHA-256 / MD5 hashes against collected file metadata
#   - IP address and domain lookups in network connection data
#   - Filepath existence checks on the live filesystem AND in collected data
#   - Process name matching against the running process snapshot
#
# Data Sources Examined:
#   - All JSON files under <output_dir>/raw/ (hash, IP, domain, filepath IOCs)
#   - Live filesystem for filepath IOC existence checks
#   - <output_dir>/raw/processes.json specifically for process_name IOCs
#
# MITRE ATT&CK Mapping:
#   Each IOC rule carries its own mitre_technique / mitre_name fields, so
#   technique attribution is delegated to the rule author. Matched findings
#   propagate these fields downstream to mitre_mapper for aggregation.
#
# Output:
#   Writes <output_dir>/analysis/ioc_scanner.json containing an array of
#   ioc_match findings, each tagged with type, severity, source, and MITRE
#   technique metadata.
# =============================================================================

# Scans collected artifacts for IOC matches and writes results to JSON.
# Usage: analyze_iocs <output_dir> <iocs_path>
# Args:
#   output_dir - Root output directory containing raw/ and analysis/ subdirs
#   iocs_path  - Path to a YAML IOC file or directory of YAML IOC files
# Output:
#   Creates analysis/ioc_scanner.json with all matches
analyze_iocs() {
    local output_dir="$1"
    local iocs_path="$2"

    local findings=()

    # Pre-declare variables used by the YAML parser. A lightweight line-by-line
    # parser is used instead of a real YAML library because IntrusionInspector
    # avoids external dependencies (Python, jq, yq) to stay maximally portable.
    local ioc_type="" ioc_value="" ioc_desc="" ioc_severity="" ioc_technique="" ioc_name=""

    # Parses a single YAML IOC file and dispatches each IOC entry to _match_ioc.
    # Usage: _scan_ioc_file <ioc_file>
    # Args:
    #   ioc_file - Path to a YAML file containing IOC definitions
    # Design:
    #   The parser accumulates fields until it encounters the next "- type:" block
    #   boundary, then flushes the previous entry. After the loop, the final
    #   entry is flushed explicitly since there is no trailing boundary marker.
    #   This streaming approach avoids loading the entire file into memory.
    _scan_ioc_file() {
        local ioc_file="$1"
        local current_type="" current_value="" current_desc="" current_severity="" current_technique="" current_name=""

        while IFS= read -r line; do
            # Strip leading whitespace for field detection; YAML indentation varies
            line="$(echo "$line" | sed 's/^[[:space:]]*//')"
            [[ -z "$line" || "$line" =~ ^# ]] && continue

            case "$line" in
                "- type: "*)       current_type="${line#*: }" ;;
                "type: "*)         current_type="${line#*: }" ;;
                # Strip quotes from values since our JSON builder handles quoting
                "value: "*)        current_value="${line#*: }"; current_value="${current_value//\"/}" ;;
                "description: "*) current_desc="${line#*: }"; current_desc="${current_desc//\"/}" ;;
                "severity: "*)     current_severity="${line#*: }" ;;
                "mitre_technique: "*) current_technique="${line#*: }"; current_technique="${current_technique//\"/}" ;;
                "mitre_name: "*)   current_name="${line#*: }"; current_name="${current_name//\"/}" ;;
                "- type: "*)
                    # New IOC entry boundary — flush the previous entry before resetting
                    if [[ -n "$current_type" && -n "$current_value" ]]; then
                        _match_ioc "$current_type" "$current_value" "$current_desc" "$current_severity" "$current_technique" "$current_name"
                    fi
                    current_type="${line#*: }"
                    current_value="" current_desc="" current_severity="" current_technique="" current_name=""
                    ;;
            esac
        done < "$ioc_file"

        # Flush the final entry — no trailing "- type:" to trigger it in the loop
        if [[ -n "$current_type" && -n "$current_value" ]]; then
            _match_ioc "$current_type" "$current_value" "$current_desc" "$current_severity" "$current_technique" "$current_name"
        fi
    }

    # Attempts to match a single IOC against collected artifacts based on its type.
    # Usage: _match_ioc <type> <value> <desc> <severity> <technique> <name>
    # Args:
    #   type      - IOC type: hash_sha256, hash_md5, ip, domain, filepath, process_name
    #   value     - The IOC value to search for (hash string, IP, domain, path, etc.)
    #   desc      - Human-readable description from the IOC rule
    #   severity  - Severity level (low/medium/high/critical); defaults to "medium"
    #   technique - MITRE ATT&CK technique ID (e.g., T1059)
    #   name      - MITRE ATT&CK technique name
    # Design:
    #   Uses simple grep-based string matching rather than structured JSON parsing.
    #   This trades precision for speed and portability — grep works on any system
    #   and handles large JSON files efficiently. False positives are acceptable in
    #   a triage tool where analysts review all findings.
    _match_ioc() {
        local type="$1" value="$2" desc="$3" severity="$4" technique="$5" name="$6"

        case "$type" in
            hash_sha256|hash_md5)
                # Search all raw JSON files for hash matches. Hashes are globally
                # unique strings so substring matching via grep is safe here.
                for raw_file in "${output_dir}/raw"/*.json; do
                    [[ -f "$raw_file" ]] || continue
                    if grep -q "$value" "$raw_file" 2>/dev/null; then
                        findings+=("$(json_object \
                            "$(json_kvs "type" "ioc_match")" \
                            "$(json_kvs "ioc_type" "$type")" \
                            "$(json_kvs "ioc_value" "$value")" \
                            "$(json_kvs "description" "$desc")" \
                            "$(json_kvs "severity" "${severity:-medium}")" \
                            "$(json_kvs "mitre_technique" "$technique")" \
                            "$(json_kvs "mitre_name" "$name")" \
                            "$(json_kvs "source" "$(basename "$raw_file")")"
                        )")
                    fi
                done
                ;;
            ip|domain)
                # IP and domain IOCs are searched across all raw collector outputs
                # because network indicators can appear in process args, logs, or
                # connection data — not just the network.json file.
                for raw_file in "${output_dir}/raw"/*.json; do
                    [[ -f "$raw_file" ]] || continue
                    if grep -q "$value" "$raw_file" 2>/dev/null; then
                        findings+=("$(json_object \
                            "$(json_kvs "type" "ioc_match")" \
                            "$(json_kvs "ioc_type" "$type")" \
                            "$(json_kvs "ioc_value" "$value")" \
                            "$(json_kvs "description" "$desc")" \
                            "$(json_kvs "severity" "${severity:-medium}")" \
                            "$(json_kvs "mitre_technique" "$technique")" \
                            "$(json_kvs "mitre_name" "$name")" \
                            "$(json_kvs "source" "$(basename "$raw_file")")"
                        )")
                    fi
                done
                ;;
            filepath)
                # Filepath IOCs are checked two ways:
                # 1. Does the file exist on the live filesystem right now?
                # 2. Was the path referenced in any collected artifact data?
                # Both checks matter: a malicious file may have been deleted but
                # still appear in logs, or it may exist but not yet be referenced.
                if [[ -f "$value" ]]; then
                    findings+=("$(json_object \
                        "$(json_kvs "type" "ioc_match")" \
                        "$(json_kvs "ioc_type" "$type")" \
                        "$(json_kvs "ioc_value" "$value")" \
                        "$(json_kvs "description" "$desc")" \
                        "$(json_kvs "severity" "${severity:-medium}")" \
                        "$(json_kvs "mitre_technique" "$technique")" \
                        "$(json_kvs "mitre_name" "$name")" \
                        "$(json_kvs "source" "filesystem")"
                    )")
                fi
                # Also check collected artifact data
                for raw_file in "${output_dir}/raw"/*.json; do
                    [[ -f "$raw_file" ]] || continue
                    if grep -q "$value" "$raw_file" 2>/dev/null; then
                        findings+=("$(json_object \
                            "$(json_kvs "type" "ioc_match")" \
                            "$(json_kvs "ioc_type" "$type")" \
                            "$(json_kvs "ioc_value" "$value")" \
                            "$(json_kvs "description" "$desc")" \
                            "$(json_kvs "severity" "${severity:-medium}")" \
                            "$(json_kvs "mitre_technique" "$technique")" \
                            "$(json_kvs "mitre_name" "$name")" \
                            "$(json_kvs "source" "$(basename "$raw_file")")"
                        )")
                    fi
                done
                ;;
            process_name)
                # Process name IOCs only check the process snapshot — if the process
                # is no longer running at collection time, it won't be caught here.
                # Historical process evidence would need to come from log-based IOCs.
                local proc_file="${output_dir}/raw/processes.json"
                if [[ -f "$proc_file" ]] && grep -q "$value" "$proc_file" 2>/dev/null; then
                    findings+=("$(json_object \
                        "$(json_kvs "type" "ioc_match")" \
                        "$(json_kvs "ioc_type" "$type")" \
                        "$(json_kvs "ioc_value" "$value")" \
                        "$(json_kvs "description" "$desc")" \
                        "$(json_kvs "severity" "${severity:-medium}")" \
                        "$(json_kvs "mitre_technique" "$technique")" \
                        "$(json_kvs "mitre_name" "$name")" \
                        "$(json_kvs "source" "processes")"
                    )")
                fi
                ;;
        esac
    }

    # Iterate over IOC rule files. Supports both a directory of YAML files and
    # a single file path, so users can point to a curated rules directory or a
    # one-off IOC list for targeted hunting.
    if [[ -d "$iocs_path" ]]; then
        for ioc_file in "$iocs_path"/*.yaml "$iocs_path"/*.yml; do
            [[ -f "$ioc_file" ]] || continue
            _scan_ioc_file "$ioc_file"
        done
    elif [[ -f "$iocs_path" ]]; then
        _scan_ioc_file "$iocs_path"
    fi

    # Build the final JSON result and write to the analysis directory.
    # The "${findings[@]+"${findings[@]}"}" pattern avoids "unbound variable"
    # errors under set -u when the findings array is empty.
    local result
    result="$(json_object \
        "$(json_kvs "analyzer" "ioc_scanner")" \
        "$(json_kvn "finding_count" "${#findings[@]}")" \
        "$(json_kv "findings" "$(json_array "${findings[@]+"${findings[@]}"}")")"
    )"

    json_write "${output_dir}/analysis/ioc_scanner.json" "$result"
    log_info "IOC scanner: ${#findings[@]} findings"
}
