#!/usr/bin/env bash
# =============================================================================
# lib/reporters/html_reporter.sh — Self-Contained HTML Report Generator
# =============================================================================
#
# Produces a single-file HTML report with an embedded dark-theme CSS design.
# The report is fully self-contained (no external CSS/JS dependencies) so it
# can be opened in any browser, attached to tickets, or emailed as-is.
#
# Architecture role:
#   One of four reporter modules (json, csv, html, console) dispatched by
#   run_reporters() via format "html" → function report_html(). This is the
#   default report format and typically the primary deliverable for incident
#   responders.
#
# Report sections:
#   1. System information cards (hostname, OS, architecture, kernel)
#   2. Risk score gauge with color-coded ring (green/amber/red)
#   3. Summary cards (total findings, MITRE technique count, case ID)
#   4. Findings table (severity, description, MITRE technique, source)
#   5. Collection summary table (collector name, artifact count, duration)
#   6. Footer with examiner name and tool version
#
# Data extraction:
#   Uses grep+sed to parse JSON values since jq may not be available. This
#   is intentionally simple pattern matching — the JSON files are produced
#   by our own json.sh builder and have predictable formatting.
#
# =============================================================================

# -----------------------------------------------------------------------------
# report_html — Build and write the self-contained HTML report
#
# Parameters:
#   $1  output_dir — Root output directory containing raw/ and analysis/
#
# Outputs:
#   ${output_dir}/report.html — Single-file dark-themed HTML report
#
# The function is structured in phases:
#   1. Extract scalar values from JSON files (system info, risk score, etc.)
#   2. Count total findings across all analyzer outputs
#   3. Build HTML table rows for findings and collector summaries
#   4. Emit the HTML document using heredocs (static template + dynamic data)
# -----------------------------------------------------------------------------
report_html() {
    local output_dir="$1"
    local html_file="${output_dir}/report.html"

    # ── Phase 1: Extract system info and risk metrics ──
    local hostname_val="" os_val="" arch_val="" kernel_val="" risk_score=0
    local technique_count=0 finding_count=0

    # Parse system_info.json for endpoint identification fields
    if [[ -f "${output_dir}/raw/system_info.json" ]]; then
        hostname_val="$(grep -o '"hostname": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        os_val="$(grep -o '"os_name": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        arch_val="$(grep -o '"architecture": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        kernel_val="$(grep -o '"kernel_version": "[^"]*"' "${output_dir}/raw/system_info.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
    fi

    # Parse MITRE summary for risk score and technique count
    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]]; then
        risk_score="$(grep -o '"risk_score": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
        technique_count="$(grep -o '"technique_count": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
    fi

    # ── Phase 2: Aggregate total finding count across all analyzers ──
    for af in "${output_dir}/analysis"/*.json; do
        [[ -f "$af" ]] || continue
        [[ "$(basename "$af")" == "mitre_attack_summary.json" || "$(basename "$af")" == "timeline.json" ]] && continue
        local fc
        fc="$(grep -o '"finding_count": [0-9]*' "$af" 2>/dev/null | head -1 | sed 's/.*: //')"
        finding_count=$(( finding_count + ${fc:-0} ))
    done

    # Color-code the risk score ring: green (0-20), amber (21-50), red (51+)
    local risk_color="#4caf50"
    [[ "${risk_score:-0}" -gt 20 ]] && risk_color="#ff9800"
    [[ "${risk_score:-0}" -gt 50 ]] && risk_color="#f44336"

    # ── Phase 3: Build HTML table rows for findings ──
    # Each finding object is extracted via a grep pattern that captures
    # single-depth JSON objects containing a "severity" key. Fields are
    # then parsed individually from each matched object.
    local findings_rows=""
    for af in "${output_dir}/analysis"/*.json; do
        [[ -f "$af" ]] || continue
        [[ "$(basename "$af")" == "mitre_attack_summary.json" || "$(basename "$af")" == "timeline.json" ]] && continue
        local analyzer_name
        analyzer_name="$(basename "$af" .json)"

        while IFS= read -r line; do
            local sev desc technique
            sev="$(echo "$line" | grep -o '"severity": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            desc="$(echo "$line" | grep -o '"description": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            technique="$(echo "$line" | grep -o '"mitre_technique": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            [[ -z "$sev" ]] && continue

            # CSS class maps to severity-based color (sev-critical, sev-high, etc.)
            local sev_class="sev-${sev}"
            findings_rows+="<tr><td class=\"${sev_class}\">${sev}</td><td>${desc}</td><td>${technique:-—}</td><td>${analyzer_name}</td></tr>"
        done < <(grep -o '{[^{}]*"severity"[^{}]*}' "$af" 2>/dev/null)
    done

    # ── Phase 4: Build HTML table rows for collector summary ──
    # Shows artifact count and collection duration for each collector
    local collector_rows=""
    for rf in "${output_dir}/raw"/*.json; do
        [[ -f "$rf" ]] || continue
        local cname acount dur
        cname="$(basename "$rf" .json)"
        acount="$(grep -o '"artifact_count": [0-9]*' "$rf" 2>/dev/null | head -1 | sed 's/.*: //')"
        dur="$(grep -o '"duration_seconds": [0-9]*' "$rf" 2>/dev/null | head -1 | sed 's/.*: //')"
        collector_rows+="<tr><td>${cname}</td><td>${acount:-0}</td><td>${dur:-0}s</td></tr>"
    done

    # Extract case metadata from chain of custody for the report header/footer
    local case_id="" examiner=""
    if [[ -f "${output_dir}/chain_of_custody.json" ]]; then
        case_id="$(grep -o '"case_id": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        examiner="$(grep -o '"examiner": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
    fi

    # ── Phase 5: Emit the HTML document ──
    # The document is split into two heredocs:
    #   1. HTMLEOF (quoted) — static HTML/CSS template, no variable expansion
    #   2. EOF (unquoted) — dynamic content with bash variable interpolation
    cat > "$html_file" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IntrusionInspector Report</title>
<style>
:root{--bg:#1a1a2e;--surface:#16213e;--card:#0f3460;--text:#e0e0e0;--text-dim:#8888aa;--accent:#00d4ff;--danger:#f44336;--warn:#ff9800;--ok:#4caf50}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}
.container{max-width:1200px;margin:0 auto}
h1{color:var(--accent);font-size:1.8rem;margin-bottom:.5rem}
h2{color:var(--accent);font-size:1.3rem;margin:2rem 0 1rem;border-bottom:1px solid var(--card);padding-bottom:.5rem}
.subtitle{color:var(--text-dim);font-size:.9rem;margin-bottom:2rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1.5rem 0}
.card{background:var(--surface);border:1px solid var(--card);border-radius:8px;padding:1.2rem}
.card-label{font-size:.8rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em}
.card-value{font-size:1.8rem;font-weight:700;margin-top:.3rem}
.risk-score{text-align:center}
.risk-ring{width:100px;height:100px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto;font-size:2rem;font-weight:700}
table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:8px;overflow:hidden;margin:1rem 0}
th{background:var(--card);color:var(--accent);text-align:left;padding:.8rem 1rem;font-size:.85rem;text-transform:uppercase;letter-spacing:.03em}
td{padding:.6rem 1rem;border-bottom:1px solid rgba(255,255,255,.05);font-size:.9rem}
tr:hover{background:rgba(0,212,255,.03)}
.sev-critical{color:#f44336;font-weight:700}
.sev-high{color:#ff5722;font-weight:600}
.sev-medium{color:#ff9800}
.sev-low{color:#ffc107}
.sev-info{color:#8888aa}
.footer{text-align:center;color:var(--text-dim);font-size:.8rem;margin-top:3rem;padding-top:1rem;border-top:1px solid var(--card)}
</style>
</head>
<body>
<div class="container">
<h1>IntrusionInspector Report</h1>
HTMLEOF

    # Append dynamic content — this heredoc is unquoted so bash variables
    # (risk_score, findings_rows, collector_rows, etc.) are interpolated
    cat >> "$html_file" <<EOF
<p class="subtitle">Generated $(utc_now) | v${VERSION}</p>

<div class="grid">
<div class="card"><div class="card-label">Hostname</div><div class="card-value">${hostname_val:-—}</div></div>
<div class="card"><div class="card-label">OS</div><div class="card-value">${os_val:-—}</div></div>
<div class="card"><div class="card-label">Architecture</div><div class="card-value">${arch_val:-—}</div></div>
<div class="card"><div class="card-label">Kernel</div><div class="card-value">${kernel_val:-—}</div></div>
</div>

<div class="grid">
<div class="card risk-score">
  <div class="card-label">Risk Score</div>
  <div class="risk-ring" style="border: 4px solid ${risk_color}">${risk_score:-0}</div>
  <div style="color:var(--text-dim);font-size:.8rem;margin-top:.5rem">/ ${MAX_RISK_SCORE}</div>
</div>
<div class="card"><div class="card-label">Total Findings</div><div class="card-value">${finding_count}</div></div>
<div class="card"><div class="card-label">MITRE Techniques</div><div class="card-value">${technique_count:-0}</div></div>
<div class="card"><div class="card-label">Case ID</div><div class="card-value" style="font-size:1rem">${case_id:-—}</div></div>
</div>

<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Description</th><th>MITRE</th><th>Source</th></tr></thead>
<tbody>
${findings_rows:-<tr><td colspan="4" style="text-align:center;color:var(--text-dim)">No findings</td></tr>}
</tbody>
</table>

<h2>Collection Summary</h2>
<table>
<thead><tr><th>Collector</th><th>Artifacts</th><th>Duration</th></tr></thead>
<tbody>
${collector_rows:-<tr><td colspan="3" style="text-align:center;color:var(--text-dim)">No data</td></tr>}
</tbody>
</table>

<div class="footer">
IntrusionInspector v${VERSION} — Generated by bash DFIR tool<br>
Examiner: ${examiner:-—}
</div>
</div>
</body>
</html>
EOF

    log_info "HTML report written to ${html_file}"
}
