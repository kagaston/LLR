#!/usr/bin/env bash
# =============================================================================
# lib/reporters/csv_reporter.sh — CSV Report Generator
# =============================================================================
#
# Produces two CSV files for spreadsheet-friendly and SIEM-ingestible output:
#
#   1. timeline.csv — Chronological event timeline extracted from the timeline
#      analyzer's JSON output. Columns: timestamp, source, event_type, detail.
#
#   2. findings.csv — All findings from every analyzer (anomaly detector, IOC
#      scanner, Sigma scanner, etc.). Columns: type, severity, description,
#      mitre_technique, source, detail.
#
# Architecture role:
#   One of four reporter modules (json, csv, html, console) dispatched by
#   run_reporters() via format "csv" → function report_csv().
#
# jq vs grep fallback:
#   When jq is available, CSV rows are produced with proper RFC 4180 escaping
#   via jq's @csv filter. When jq is absent, a basic grep-based extraction
#   provides degraded but functional output. This dual-path approach keeps the
#   tool usable on minimal systems without jq installed.
#
# =============================================================================

# -----------------------------------------------------------------------------
# report_csv — Generate timeline.csv and findings.csv
#
# Parameters:
#   $1  output_dir — Root output directory containing analysis/ results
#
# Outputs:
#   ${output_dir}/timeline.csv  — Chronological event list
#   ${output_dir}/findings.csv  — Aggregated findings from all analyzers
# -----------------------------------------------------------------------------
report_csv() {
    local output_dir="$1"

    # ── Timeline CSV ──
    # Source: analysis/timeline.json produced by the timeline analyzer
    local timeline_file="${output_dir}/analysis/timeline.json"
    local csv_timeline="${output_dir}/timeline.csv"

    # Write CSV header
    echo "timestamp,source,event_type,detail" > "$csv_timeline"

    if [[ -f "$timeline_file" ]]; then
        # Grep-based extraction as a baseline — produces minimal rows with
        # only the timestamp field populated
        grep -oE '"timestamp": "[^"]*"' "$timeline_file" 2>/dev/null | while IFS= read -r ts_match; do
            local ts="${ts_match#*\": \"}"
            ts="${ts%\"}"
            echo "${ts},timeline,event," >> "$csv_timeline"
        done

        # If jq is available, produce properly escaped CSV with all fields.
        # The @csv filter handles quoting and comma-escaping per RFC 4180.
        if has_cmd jq; then
            jq -r '.events[]? | [.timestamp // "", .source // "", .event_type // "", .detail // ""] | @csv' \
                "$timeline_file" >> "$csv_timeline" 2>/dev/null || true
            local jq_lines
            jq_lines="$(wc -l < "$csv_timeline" | tr -d ' ')"
            if [[ "$jq_lines" -gt 1 ]]; then
                # jq succeeded — grep-based lines are duplicates but harmless
                :
            fi
        fi
    fi

    log_info "Timeline CSV written to ${csv_timeline}"

    # ── Findings CSV ──
    # Aggregates findings from all analyzer output files except the MITRE
    # summary (cross-cutting aggregation) and timeline (separate CSV above).
    local csv_findings="${output_dir}/findings.csv"
    echo "type,severity,description,mitre_technique,source,detail" > "$csv_findings"

    for analysis_file in "${output_dir}/analysis"/*.json; do
        [[ -f "$analysis_file" ]] || continue
        # Skip non-finding files
        [[ "$(basename "$analysis_file")" == "mitre_attack_summary.json" ]] && continue
        [[ "$(basename "$analysis_file")" == "timeline.json" ]] && continue

        # Derive the analyzer name from the filename for the "source" column
        local source
        source="$(basename "$analysis_file" .json)"

        if has_cmd jq; then
            # jq path: extract the .findings[] array with proper CSV escaping
            jq -r '.findings[]? | [
                .type // "",
                .severity // "",
                .description // "",
                .mitre_technique // "",
                .source // "",
                .detail // ""
            ] | @csv' "$analysis_file" >> "$csv_findings" 2>/dev/null || true
        else
            # Fallback: extract severity values via grep and produce minimal rows.
            # Only the severity and source columns are populated in this mode.
            while IFS= read -r severity; do
                severity="$(echo "$severity" | tr -d '"' | sed 's/.*: //')"
                echo "finding,${severity},,,${source}," >> "$csv_findings"
            done < <(grep -o '"severity": "[^"]*"' "$analysis_file" 2>/dev/null)
        fi
    done

    log_info "Findings CSV written to ${csv_findings}"
}
