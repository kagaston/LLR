#!/usr/bin/env bash
# =============================================================================
# lib/reporters/json_reporter.sh — JSON Report Generator
# =============================================================================
#
# Aggregates all raw collector output, analysis results, MITRE ATT&CK summary,
# and chain of custody metadata into a single unified report.json file.
#
# Architecture role:
#   This reporter is one of four output formats (json, csv, html, console)
#   invoked by the engine's run_reporters() via convention-based dispatch
#   (format "json" → function report_json). It reads from the raw/ and
#   analysis/ subdirectories and produces a self-contained JSON document
#   suitable for ingestion by SIEMs, ticketing systems, or other tooling.
#
# Output structure:
#   {
#     "tool": "intrusion-inspector",
#     "version": "...",
#     "generated_at": "...",
#     "system_info": { ... },
#     "collector_results": [ ... ],
#     "analysis_results": [ ... ],
#     "mitre_summary": { ... },
#     "chain_of_custody": { ... }
#   }
#
# Dependencies:
#   - json_object, json_kvs, json_kv, json_write from lib/core/json.sh
#   - utc_now from lib/core/utils.sh
#   - VERSION from lib/core/config.sh
#
# =============================================================================

# -----------------------------------------------------------------------------
# report_json — Build and write the consolidated JSON report
#
# Parameters:
#   $1  output_dir — Root output directory containing raw/ and analysis/
#
# Reads every .json file from raw/ (collector outputs) and analysis/
# (analyzer findings), plus the MITRE summary and chain of custody,
# then assembles them into a single JSON document using the pure-bash
# JSON builder helpers.
#
# The MITRE summary is separated from other analysis results because it
# represents a cross-cutting aggregation rather than a single analyzer's
# output.
# -----------------------------------------------------------------------------
report_json() {
    local output_dir="$1"

    # Load system_info.json if the system_info collector ran; otherwise
    # default to an empty object so the JSON structure is always valid
    local sys_info="{}"
    if [[ -f "${output_dir}/raw/system_info.json" ]]; then
        sys_info="$(cat "${output_dir}/raw/system_info.json")"
    fi

    # Concatenate all raw collector JSON files into a JSON array.
    # Each collector writes one .json file to raw/, so every file is
    # included verbatim as an element.
    local collectors="["
    local first=true
    for raw_file in "${output_dir}/raw"/*.json; do
        [[ -f "$raw_file" ]] || continue
        if [[ "$first" == "true" ]]; then first=false; else collectors+=", "; fi
        collectors+="$(cat "$raw_file")"
    done
    collectors+="]"

    # Concatenate analysis results into a JSON array, excluding the MITRE
    # summary which gets its own top-level key for easier consumption
    local analyses="["
    first=true
    for analysis_file in "${output_dir}/analysis"/*.json; do
        [[ -f "$analysis_file" ]] || continue
        [[ "$(basename "$analysis_file")" == "mitre_attack_summary.json" ]] && continue
        if [[ "$first" == "true" ]]; then first=false; else analyses+=", "; fi
        analyses+="$(cat "$analysis_file")"
    done
    analyses+="]"

    # MITRE ATT&CK summary as a standalone object
    local mitre="{}"
    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]]; then
        mitre="$(cat "${output_dir}/analysis/mitre_attack_summary.json")"
    fi

    # Chain of custody metadata (case_id, examiner, timestamps, etc.)
    local coc="{}"
    if [[ -f "${output_dir}/chain_of_custody.json" ]]; then
        coc="$(cat "${output_dir}/chain_of_custody.json")"
    fi

    # Assemble the final report using pure-bash JSON builder helpers.
    # json_kvs produces "key": "string_value" pairs,
    # json_kv produces "key": <raw_json_value> pairs.
    local report
    report="$(json_object \
        "$(json_kvs "tool" "intrusion-inspector")" \
        "$(json_kvs "version" "$VERSION")" \
        "$(json_kvs "generated_at" "$(utc_now)")" \
        "$(json_kv "system_info" "$sys_info")" \
        "$(json_kv "collector_results" "$collectors")" \
        "$(json_kv "analysis_results" "$analyses")" \
        "$(json_kv "mitre_summary" "$mitre")" \
        "$(json_kv "chain_of_custody" "$coc")"
    )"

    json_write "${output_dir}/report.json" "$report"
    log_info "JSON report written to ${output_dir}/report.json"
}
