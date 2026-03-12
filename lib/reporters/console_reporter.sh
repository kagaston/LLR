#!/usr/bin/env bash
# =============================================================================
# lib/reporters/console_reporter.sh — ANSI-Colored Terminal Report
# =============================================================================
#
# Renders the triage report directly to the terminal with ANSI color codes and
# Unicode box-drawing characters for a polished CLI experience. Designed for
# quick visual triage by incident responders who want an immediate summary
# without opening a browser or spreadsheet.
#
# Architecture role:
#   One of four reporter modules (json, csv, html, console) dispatched by
#   run_reporters() via format "console" → function report_console().
#
# Output sections (mirroring the HTML report):
#   1. Box-drawn header banner with version
#   2. System information (hostname, OS, architecture)
#   3. Color-coded risk score (green ≤20, yellow 21-50, red >50)
#   4. MITRE ATT&CK technique list with arrow indicators
#   5. Severity-colored findings list (critical/high=red, medium=yellow, etc.)
#   6. Collector summary table (name, artifact count, duration)
#
# All output goes to stderr so it doesn't interfere with stdout piping.
# Color variables ($_CLR_*) are defined in lib/core/logging.sh.
#
# =============================================================================

# -----------------------------------------------------------------------------
# report_console — Render a color-coded report summary to the terminal
#
# Parameters:
#   $1  output_dir — Root output directory containing raw/ and analysis/
#
# Reads the same JSON sources as the HTML reporter but renders to stderr
# using printf with ANSI escape sequences. No file output is produced.
# -----------------------------------------------------------------------------
report_console() {
    local output_dir="$1"

    # ── Extract system info and risk metrics ──
    local hostname_val="" os_val="" arch_val="" risk_score=0 technique_count=0

    if [[ -f "${output_dir}/raw/system_info.json" ]]; then
        hostname_val="$(grep -o '"hostname": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        os_val="$(grep -o '"os_name": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        arch_val="$(grep -o '"architecture": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
    fi

    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]]; then
        risk_score="$(grep -o '"risk_score": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
        technique_count="$(grep -o '"technique_count": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
    fi

    # Map risk score to ANSI color: green (safe), yellow (warning), red (danger)
    local risk_clr="$_CLR_GREEN"
    [[ "${risk_score:-0}" -gt 20 ]] && risk_clr="$_CLR_YELLOW"
    [[ "${risk_score:-0}" -gt 50 ]] && risk_clr="$_CLR_RED"

    # ── Report header — Unicode box-drawing banner ──
    printf '\n%b' "$_CLR_CYAN" >&2
    printf '╔══════════════════════════════════════════════════════════╗\n' >&2
    printf '║          IntrusionInspector Report v%-20s ║\n' "${VERSION}" >&2
    printf '╚══════════════════════════════════════════════════════════╝\n' >&2
    printf '%b\n' "$_CLR_RESET" >&2

    # ── System information section ──
    printf '%b  System Information%b\n' "$_CLR_BOLD" "$_CLR_RESET" >&2
    printf '  %-16s %s\n' "Hostname:" "${hostname_val:-—}" >&2
    printf '  %-16s %s\n' "OS:" "${os_val:-—}" >&2
    printf '  %-16s %s\n' "Architecture:" "${arch_val:-—}" >&2
    printf '\n' >&2

    # ── Risk score with severity coloring ──
    printf '%b  Risk Score: %b%s%b / %s%b\n\n' "$_CLR_BOLD" "$risk_clr" "${risk_score:-0}" "$_CLR_RESET" "$MAX_RISK_SCORE" "$_CLR_RESET" >&2

    # ── MITRE ATT&CK technique listing ──
    printf '%b  MITRE ATT&CK: %s techniques detected%b\n' "$_CLR_BOLD" "${technique_count:-0}" "$_CLR_RESET" >&2

    # List each detected technique ID with a cyan arrow prefix
    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]]; then
        while IFS= read -r tid; do
            tid="$(echo "$tid" | tr -d '"' | sed 's/.*: //')"
            [[ -z "$tid" ]] && continue
            printf '    %b→%b %s\n' "$_CLR_CYAN" "$_CLR_RESET" "$tid" >&2
        done < <(grep -o '"technique_id": "[^"]*"' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null)
    fi
    printf '\n' >&2

    # ── Findings section — severity-colored list ──
    printf '%b  Findings%b\n' "$_CLR_BOLD" "$_CLR_RESET" >&2

    local total_findings=0
    for af in "${output_dir}/analysis"/*.json; do
        [[ -f "$af" ]] || continue
        [[ "$(basename "$af")" == "mitre_attack_summary.json" || "$(basename "$af")" == "timeline.json" ]] && continue

        # Extract individual finding objects and render each one
        while IFS= read -r line; do
            local sev desc
            sev="$(echo "$line" | grep -o '"severity": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            desc="$(echo "$line" | grep -o '"description": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            [[ -z "$sev" ]] && continue

            # Map severity to ANSI color for visual triage
            local sev_clr
            case "$sev" in
                critical) sev_clr="$_CLR_RED" ;;
                high)     sev_clr="$_CLR_RED" ;;
                medium)   sev_clr="$_CLR_YELLOW" ;;
                low)      sev_clr="$_CLR_DIM" ;;
                *)        sev_clr="$_CLR_RESET" ;;
            esac

            printf '    %b[%-8s]%b %s\n' "$sev_clr" "$sev" "$_CLR_RESET" "$desc" >&2
            total_findings=$((total_findings + 1))
        done < <(grep -o '{[^{}]*"severity"[^{}]*}' "$af" 2>/dev/null)
    done

    [[ "$total_findings" -eq 0 ]] && printf '    %b(no findings)%b\n' "$_CLR_DIM" "$_CLR_RESET" >&2

    printf '\n' >&2

    # ── Collector summary table ──
    # Tabular layout showing what each collector gathered and how long it took
    printf '%b  Collection Summary%b\n' "$_CLR_BOLD" "$_CLR_RESET" >&2
    printf '  %-24s %10s %10s\n' "Collector" "Artifacts" "Duration" >&2
    printf '  %-24s %10s %10s\n' "────────────────────────" "─────────" "────────" >&2

    for rf in "${output_dir}/raw"/*.json; do
        [[ -f "$rf" ]] || continue
        local cname acount dur
        cname="$(basename "$rf" .json)"
        acount="$(grep -o '"artifact_count": [0-9]*' "$rf" 2>/dev/null | head -1 | sed 's/.*: //')"
        dur="$(grep -o '"duration_seconds": [0-9]*' "$rf" 2>/dev/null | head -1 | sed 's/.*: //')"
        printf '  %-24s %10s %9ss\n' "$cname" "${acount:-0}" "${dur:-0}" >&2
    done

    printf '\n' >&2
}
