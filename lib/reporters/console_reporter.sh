#!/usr/bin/env bash
# =============================================================================
# lib/reporters/console_reporter.sh — Rich ANSI Terminal Report
# =============================================================================
#
# Produces a comprehensive terminal report using ANSI escape codes for color
# and formatting. Modelled after the Python IntrusionInspector Rich-based
# console reporter, but implemented with pure bash and printf.
#
# All output goes to stderr so it does not interfere with stdout-based
# piping or JSON output. The report includes:
#
#   1. Header banner with tool name and case metadata
#   2. Risk score with severity label and color coding
#   3. Findings summary breakdown by severity level
#   4. Detailed findings list with index numbers and MITRE references
#   5. System information overview
#   6. MITRE ATT&CK technique tree grouped by tactic
#   7. Collection summary table with artifact counts and durations
#
# =============================================================================

# -----------------------------------------------------------------------------
# report_console — Generate the full ANSI-colored terminal report
#
# Parameters:
#   $1  output_dir — Root output directory containing raw/ and analysis/
#
# Output:
#   All output to stderr via printf/echo >&2
#
# Design:
#   Uses the _CLR_* color variables from logging.sh for consistent theming.
#   Box-drawing characters (Unicode) create visual structure. Each section
#   is a self-contained block with clear headers for easy scanning.
# -----------------------------------------------------------------------------
report_console() {
    local output_dir="$1"

    # ── Extract system info ──
    local hostname_val="" os_val="" os_version="" arch_val=""
    if [[ -f "${output_dir}/raw/system_info.json" ]]; then
        hostname_val="$(grep -o '"hostname": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        os_val="$(grep -o '"os_name": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        os_version="$(grep -o '"os_version": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        arch_val="$(grep -o '"architecture": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
    fi

    # ── Extract risk metrics ──
    local risk_score=0 technique_count=0
    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]]; then
        risk_score="$(grep -o '"risk_score": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
        technique_count="$(grep -o '"technique_count": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
    fi

    # ── Extract case info ──
    local case_id="" examiner=""
    if [[ -f "${output_dir}/chain_of_custody.json" ]]; then
        case_id="$(grep -o '"case_id": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        examiner="$(grep -o '"examiner": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
    fi

    # ── Count findings by severity ──
    local count_critical=0 count_high=0 count_medium=0 count_low=0 count_info=0
    for af in "${output_dir}/analysis"/*.json; do
        [[ -f "$af" ]] || continue
        [[ "$(basename "$af")" == "mitre_attack_summary.json" || "$(basename "$af")" == "timeline.json" ]] && continue
        while IFS= read -r sev; do
            sev="$(echo "$sev" | sed 's/.*": "//;s/"//')"
            case "$sev" in
                critical) count_critical=$((count_critical + 1)) ;;
                high)     count_high=$((count_high + 1)) ;;
                medium)   count_medium=$((count_medium + 1)) ;;
                low)      count_low=$((count_low + 1)) ;;
                info)     count_info=$((count_info + 1)) ;;
            esac
        done < <(grep -o '"severity": "[^"]*"' "$af" 2>/dev/null)
    done
    local total_findings=$((count_critical + count_high + count_medium + count_low + count_info))

    # Risk level label and color
    local risk_clr="$_CLR_GREEN" risk_label="CLEAN"
    if [[ "${risk_score:-0}" -ge 70 ]]; then
        risk_clr="$_CLR_RED"; risk_label="CRITICAL"
    elif [[ "${risk_score:-0}" -ge 40 ]]; then
        risk_clr="$_CLR_RED"; risk_label="HIGH"
    elif [[ "${risk_score:-0}" -ge 20 ]]; then
        risk_clr="$_CLR_YELLOW"; risk_label="MEDIUM"
    elif [[ "${risk_score:-0}" -ge 5 ]]; then
        risk_clr="$_CLR_CYAN"; risk_label="LOW"
    fi

    # ════════════════════════════════════════════════════════════════
    # Section 1: Header banner
    # ════════════════════════════════════════════════════════════════
    printf '\n' >&2
    printf '%b╔══════════════════════════════════════════════════════════════╗%b\n' "$_CLR_CYAN" "$_CLR_RESET" >&2
    printf '%b║      IntrusionInspector — DFIR Triage Report  v%-12s ║%b\n' "$_CLR_CYAN" "${VERSION}" "$_CLR_RESET" >&2
    printf '%b╚══════════════════════════════════════════════════════════════╝%b\n' "$_CLR_CYAN" "$_CLR_RESET" >&2

    [[ -n "$case_id" ]] && printf '  %bCase ID:%b    %s\n' "$_CLR_BOLD" "$_CLR_RESET" "$case_id" >&2
    [[ -n "$examiner" ]] && printf '  %bExaminer:%b   %s\n' "$_CLR_BOLD" "$_CLR_RESET" "$examiner" >&2
    [[ -n "$hostname_val" ]] && printf '  %bHost:%b       %s\n' "$_CLR_BOLD" "$_CLR_RESET" "$hostname_val" >&2
    [[ -n "$os_val" ]] && printf '  %bOS:%b         %s %s (%s)\n' "$_CLR_BOLD" "$_CLR_RESET" "$os_val" "$os_version" "$arch_val" >&2
    printf '\n' >&2

    # ════════════════════════════════════════════════════════════════
    # Section 2: Risk score
    # ════════════════════════════════════════════════════════════════
    printf '  %bRisk Score:%b  %b%s/100 (%s)%b\n' \
        "$_CLR_BOLD" "$_CLR_RESET" "$risk_clr" "${risk_score:-0}" "$risk_label" "$_CLR_RESET" >&2
    printf '\n' >&2

    # ════════════════════════════════════════════════════════════════
    # Section 3: Findings summary by severity
    # ════════════════════════════════════════════════════════════════
    printf '  %bFindings Summary%b\n' "$_CLR_BOLD" "$_CLR_RESET" >&2
    printf '  %-12s %s\n' "Severity" "Count" >&2
    printf '  %-12s %s\n' "────────────" "─────" >&2
    printf '  %b%-12s%b %d\n' "$_CLR_RED"    "CRITICAL" "$_CLR_RESET" "$count_critical" >&2
    printf '  %b%-12s%b %d\n' "$_CLR_RED"    "HIGH"     "$_CLR_RESET" "$count_high" >&2
    printf '  %b%-12s%b %d\n' "$_CLR_YELLOW" "MEDIUM"   "$_CLR_RESET" "$count_medium" >&2
    printf '  %b%-12s%b %d\n' "$_CLR_CYAN"   "LOW"      "$_CLR_RESET" "$count_low" >&2
    printf '  %b%-12s%b %d\n' "$_CLR_DIM"    "INFO"     "$_CLR_RESET" "$count_info" >&2
    printf '  %-12s %s\n' "────────────" "─────" >&2
    printf '  %-12s %d\n' "Total" "$total_findings" >&2
    printf '\n' >&2

    # ════════════════════════════════════════════════════════════════
    # Section 4: Detailed findings with index numbers
    # ════════════════════════════════════════════════════════════════
    printf '  %bDetailed Findings%b\n' "$_CLR_BOLD" "$_CLR_RESET" >&2

    if [[ "$total_findings" -eq 0 ]]; then
        printf '    %b(no findings detected)%b\n' "$_CLR_GREEN" "$_CLR_RESET" >&2
    else
        local finding_idx=0
        for af in "${output_dir}/analysis"/*.json; do
            [[ -f "$af" ]] || continue
            [[ "$(basename "$af")" == "mitre_attack_summary.json" || "$(basename "$af")" == "timeline.json" ]] && continue

            while IFS= read -r line; do
                local sev desc technique source_name
                sev="$(echo "$line" | grep -o '"severity": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
                desc="$(echo "$line" | grep -o '"description": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
                technique="$(echo "$line" | grep -o '"mitre_technique": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
                source_name="$(echo "$line" | grep -o '"source": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
                [[ -z "$sev" ]] && continue

                finding_idx=$((finding_idx + 1))
                local sev_clr
                case "$sev" in
                    critical) sev_clr="$_CLR_RED" ;;
                    high)     sev_clr="$_CLR_RED" ;;
                    medium)   sev_clr="$_CLR_YELLOW" ;;
                    low)      sev_clr="$_CLR_CYAN" ;;
                    *)        sev_clr="$_CLR_DIM" ;;
                esac

                local mitre_str=""
                [[ -n "$technique" ]] && mitre_str=" [${technique}]"

                printf '\n    %b%2d. [%-8s]%s%b %s\n' \
                    "$sev_clr" "$finding_idx" "$sev" "$mitre_str" "$_CLR_RESET" "$desc" >&2
                [[ -n "$source_name" ]] && printf '        %bSource: %s%b\n' "$_CLR_DIM" "$source_name" "$_CLR_RESET" >&2
            done < <(grep -o '{[^{}]*"severity"[^{}]*}' "$af" 2>/dev/null)
        done
    fi
    printf '\n' >&2

    # ════════════════════════════════════════════════════════════════
    # Section 5: System information
    # ════════════════════════════════════════════════════════════════
    if [[ -f "${output_dir}/raw/system_info.json" ]]; then
        printf '  %bSystem Overview%b\n' "$_CLR_BOLD" "$_CLR_RESET" >&2
        printf '  %-18s %s\n' "Field" "Value" >&2
        printf '  %-18s %s\n' "──────────────────" "──────────────────────────────────" >&2

        # Read key-value pairs from the system info artifact
        while IFS= read -r kv; do
            local key val
            key="$(echo "$kv" | sed 's/^"//;s/": .*//')"
            val="$(echo "$kv" | sed 's/^[^:]*: "//;s/"$//' | sed 's/^[^:]*: //')"
            # Skip complex/nested fields and internal fields
            [[ "$key" == "network_interfaces" || "$key" == "artifacts" ]] && continue
            [[ "$key" == "collector_name" || "$key" == "platform" || "$key" == "collected_at" ]] && continue
            [[ "$key" == "duration_seconds" || "$key" == "artifact_count" ]] && continue
            printf '  %-18s %s\n' "$key" "$val" >&2
        done < <(grep -oE '"[a-z_]+": ("[^"]*"|[0-9]+)' "${output_dir}/raw/system_info.json" 2>/dev/null | head -20)

        printf '\n' >&2
    fi

    # ════════════════════════════════════════════════════════════════
    # Section 6: MITRE ATT&CK technique tree
    # ════════════════════════════════════════════════════════════════
    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]] && [[ "${technique_count:-0}" -gt 0 ]]; then
        printf '  %bMITRE ATT&CK Coverage%b  (%s techniques)\n' "$_CLR_BOLD" "$_CLR_RESET" "${technique_count}" >&2

        # Group techniques by tactic for tree display
        local current_tactic=""
        while IFS= read -r line; do
            local tid tactic tcount
            tid="$(echo "$line" | grep -o '"technique_id": "[^"]*"' | sed 's/.*": "//;s/"//')"
            tactic="$(echo "$line" | grep -o '"tactic": "[^"]*"' | sed 's/.*": "//;s/"//')"
            tcount="$(echo "$line" | grep -o '"count": [0-9]*' | sed 's/.*: //')"
            [[ -z "$tid" ]] && continue

            # Print tactic header when tactic changes
            if [[ "$tactic" != "$current_tactic" ]]; then
                current_tactic="$tactic"
                printf '    %b├─ %s%b\n' "$_CLR_BOLD" "$tactic" "$_CLR_RESET" >&2
            fi
            printf '    │  %b→%b %s  (%s findings)\n' "$_CLR_CYAN" "$_CLR_RESET" "$tid" "${tcount:-0}" >&2
        done < <(grep -o '{[^{}]*"technique_id"[^{}]*}' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null)
        printf '\n' >&2
    fi

    # ════════════════════════════════════════════════════════════════
    # Section 7: Collection summary table
    # ════════════════════════════════════════════════════════════════
    printf '  %bCollection Summary%b\n' "$_CLR_BOLD" "$_CLR_RESET" >&2
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
