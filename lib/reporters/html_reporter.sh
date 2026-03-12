#!/usr/bin/env bash
# =============================================================================
# lib/reporters/html_reporter.sh — Full-Featured Self-Contained HTML Report
# =============================================================================
#
# Produces a single-file HTML report modelled after the Python IntrusionInspector
# HTML reporter. The report is fully self-contained — all CSS and JavaScript are
# inline — so it can be opened in any modern browser, attached to tickets, or
# emailed without external dependencies.
#
# Architecture role:
#   One of four reporter modules (json, csv, html, console) dispatched by
#   run_reporters() via format "html" → function report_html(). This is the
#   default and primary report format for incident responders.
#
# Report sections (matching the Python version):
#   1. Sticky navigation bar with section jump links
#   2. Executive summary cards (hostname, OS, architecture, kernel)
#   3. Risk score gauge with SVG ring and severity label
#   4. Findings summary by severity (critical/high/medium/low/info counts)
#   5. MITRE ATT&CK technique list grouped by tactic
#   6. Detailed findings table (sortable, collapsible by severity)
#   7. System overview table
#   8. Collector summary table (name, artifact count, duration)
#   9. Timeline section with search/filter functionality
#  10. Footer with case metadata and tool version
#
# Data extraction:
#   Uses grep+sed to parse JSON values since jq may not be available. This is
#   intentionally simple pattern matching — the JSON files are produced by our
#   own json.sh builder and have predictable formatting.
#
# Design decisions:
#   - CSS custom properties (variables) enable consistent dark-theme styling.
#   - JavaScript is minimal and progressive — the report is fully readable
#     without JS, but JS adds search, filter, and section toggle features.
#   - The heredoc is split: quoted (HTMLEOF) for static template, unquoted
#     (EOF) for dynamic bash-interpolated content.
#
# =============================================================================

# -----------------------------------------------------------------------------
# report_html — Build and write the full-featured HTML report
#
# Parameters:
#   $1  output_dir — Root output directory containing raw/ and analysis/
#
# Outputs:
#   ${output_dir}/report.html — Single-file dark-themed HTML report
#
# Phases:
#   1. Extract system info, risk metrics, and case metadata from JSON files
#   2. Build severity breakdown counts for the summary cards
#   3. Build MITRE ATT&CK technique rows grouped by tactic
#   4. Build findings table rows with severity-based CSS classes
#   5. Build collector summary table rows
#   6. Build timeline entries for the searchable timeline section
#   7. Emit the complete HTML document via heredocs
# -----------------------------------------------------------------------------
report_html() {
    local output_dir="$1"
    local html_file="${output_dir}/report.html"

    # ── Phase 1: Extract system info and risk metrics ──
    local hostname_val="" os_val="" os_version="" arch_val="" kernel_val=""
    local cpu_model="" ram_mb="" boot_time="" uptime_sec=""
    local risk_score=0 technique_count=0 finding_count=0

    if [[ -f "${output_dir}/raw/system_info.json" ]]; then
        local sysfile="${output_dir}/raw/system_info.json"
        hostname_val="$(grep -o '"hostname": "[^"]*"' "$sysfile" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        os_val="$(grep -o '"os_name": "[^"]*"' "$sysfile" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        os_version="$(grep -o '"os_version": "[^"]*"' "$sysfile" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        arch_val="$(grep -o '"architecture": "[^"]*"' "$sysfile" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        kernel_val="$(grep -o '"kernel_version": "[^"]*"' "$sysfile" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        cpu_model="$(grep -o '"cpu_model": "[^"]*"' "$sysfile" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        ram_mb="$(grep -o '"ram_total_mb": [0-9]*' "$sysfile" 2>/dev/null | head -1 | sed 's/.*: //')"
        boot_time="$(grep -o '"boot_time": "[^"]*"' "$sysfile" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        uptime_sec="$(grep -o '"uptime_seconds": [0-9]*' "$sysfile" 2>/dev/null | head -1 | sed 's/.*: //')"
    fi

    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]]; then
        risk_score="$(grep -o '"risk_score": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
        technique_count="$(grep -o '"technique_count": [0-9]*' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null | head -1 | sed 's/.*: //')"
    fi

    local case_id="" examiner="" collection_start="" collection_end=""
    if [[ -f "${output_dir}/chain_of_custody.json" ]]; then
        case_id="$(grep -o '"case_id": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        examiner="$(grep -o '"examiner": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        collection_start="$(grep -o '"collection_start": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        collection_end="$(grep -o '"collection_end": "[^"]*"' "${output_dir}/chain_of_custody.json" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
    fi

    # ── Phase 2: Severity breakdown counts ──
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
    finding_count=$((count_critical + count_high + count_medium + count_low + count_info))

    # Risk level label and SVG color
    local risk_label="CLEAN" risk_color="#4caf50"
    if [[ "${risk_score:-0}" -ge 70 ]]; then
        risk_label="CRITICAL"; risk_color="#dc2626"
    elif [[ "${risk_score:-0}" -ge 40 ]]; then
        risk_label="HIGH"; risk_color="#ea580c"
    elif [[ "${risk_score:-0}" -ge 20 ]]; then
        risk_label="MEDIUM"; risk_color="#ca8a04"
    elif [[ "${risk_score:-0}" -ge 5 ]]; then
        risk_label="LOW"; risk_color="#0891b2"
    fi

    # ── Phase 3: MITRE ATT&CK technique rows ──
    local mitre_rows=""
    if [[ -f "${output_dir}/analysis/mitre_attack_summary.json" ]]; then
        while IFS= read -r line; do
            local tid tactic tcount
            tid="$(echo "$line" | grep -o '"technique_id": "[^"]*"' | sed 's/.*": "//;s/"//')"
            tactic="$(echo "$line" | grep -o '"tactic": "[^"]*"' | sed 's/.*": "//;s/"//')"
            tcount="$(echo "$line" | grep -o '"count": [0-9]*' | sed 's/.*: //')"
            [[ -z "$tid" ]] && continue
            mitre_rows+="<tr><td><code>${tid}</code></td><td>${tactic}</td><td>${tcount:-0}</td>"
            mitre_rows+="<td><a href=\"https://attack.mitre.org/techniques/${tid//.//}/\" target=\"_blank\" rel=\"noopener\">View</a></td></tr>"
        done < <(grep -o '{[^{}]*"technique_id"[^{}]*}' "${output_dir}/analysis/mitre_attack_summary.json" 2>/dev/null)
    fi

    # ── Phase 4: Findings table rows ──
    local findings_rows=""
    local finding_idx=0
    for af in "${output_dir}/analysis"/*.json; do
        [[ -f "$af" ]] || continue
        [[ "$(basename "$af")" == "mitre_attack_summary.json" || "$(basename "$af")" == "timeline.json" ]] && continue
        local analyzer_name
        analyzer_name="$(basename "$af" .json)"

        while IFS= read -r line; do
            local sev desc technique detail check
            sev="$(echo "$line" | grep -o '"severity": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            desc="$(echo "$line" | grep -o '"description": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            technique="$(echo "$line" | grep -o '"mitre_technique": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            detail="$(echo "$line" | grep -o '"detail": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            [[ -z "$sev" ]] && continue

            finding_idx=$((finding_idx + 1))
            local sev_class="sev-${sev}"
            local technique_link=""
            if [[ -n "$technique" ]]; then
                technique_link="<a href=\"https://attack.mitre.org/techniques/${technique//.//}/\" target=\"_blank\" rel=\"noopener\">${technique}</a>"
            else
                technique_link="—"
            fi
            findings_rows+="<tr class=\"finding-row\" data-severity=\"${sev}\">"
            findings_rows+="<td>${finding_idx}</td>"
            findings_rows+="<td><span class=\"sev-badge ${sev_class}\">${sev}</span></td>"
            findings_rows+="<td>${desc}</td>"
            findings_rows+="<td>${technique_link}</td>"
            findings_rows+="<td>${analyzer_name}</td>"
            findings_rows+="</tr>"
        done < <(grep -o '{[^{}]*"severity"[^{}]*}' "$af" 2>/dev/null)
    done

    # ── Phase 5: Collector summary rows ──
    local collector_rows=""
    local total_artifacts=0
    for rf in "${output_dir}/raw"/*.json; do
        [[ -f "$rf" ]] || continue
        local cname acount dur
        cname="$(basename "$rf" .json)"
        acount="$(grep -o '"artifact_count": [0-9]*' "$rf" 2>/dev/null | head -1 | sed 's/.*: //')"
        dur="$(grep -o '"duration_seconds": [0-9]*' "$rf" 2>/dev/null | head -1 | sed 's/.*: //')"
        total_artifacts=$(( total_artifacts + ${acount:-0} ))
        collector_rows+="<tr><td>${cname}</td><td>${acount:-0}</td><td>${dur:-0}s</td></tr>"
    done

    # ── Phase 6: Timeline entries ──
    local timeline_rows=""
    if [[ -f "${output_dir}/analysis/timeline.json" ]]; then
        while IFS= read -r line; do
            local ts src etype edetail
            ts="$(echo "$line" | grep -o '"timestamp": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            src="$(echo "$line" | grep -o '"source": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            etype="$(echo "$line" | grep -o '"event_type": "[^"]*"' | head -1 | sed 's/.*": "//;s/"//')"
            [[ -z "$ts" ]] && continue
            timeline_rows+="<tr class=\"timeline-row\"><td>${ts}</td><td>${src}</td><td>${etype:-event}</td></tr>"
        done < <(grep -o '{[^{}]*"timestamp"[^{}]*}' "${output_dir}/analysis/timeline.json" 2>/dev/null | head -200)
    fi

    # ── Phase 7: Emit HTML document ──

    # Part 1: Static HTML/CSS/JS template (quoted heredoc — no variable expansion)
    cat > "$html_file" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IntrusionInspector Report</title>
<style>
:root{
  --bg:#111827;--surface:#1f2937;--card:#1e293b;--border:#334155;
  --text:#f1f5f9;--text-sec:#94a3b8;--text-muted:#64748b;
  --accent:#3b82f6;--accent-dim:#1e3a5f;
  --sev-crit:#dc2626;--sev-high:#ea580c;--sev-med:#ca8a04;--sev-low:#0891b2;--sev-info:#6b7280;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:'SF Mono','Fira Code',Consolas,monospace;
  --radius:8px
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.6}

/* Sticky nav */
nav{position:sticky;top:0;z-index:100;background:rgba(17,24,39,.95);backdrop-filter:blur(8px);border-bottom:1px solid var(--border);padding:.6rem 2rem;display:flex;gap:1.5rem;align-items:center;flex-wrap:wrap}
nav a{color:var(--text-sec);text-decoration:none;font-size:.85rem;transition:color .2s}
nav a:hover{color:var(--accent)}
nav .brand{color:var(--accent);font-weight:700;font-size:1rem;margin-right:auto}

.container{max-width:1300px;margin:0 auto;padding:2rem}
h1{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}
h2{color:var(--accent);font-size:1.3rem;margin:2.5rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border);cursor:pointer}
h2:hover{opacity:.8}
h2::before{content:'▼ ';font-size:.7rem;color:var(--text-muted)}
h2.collapsed::before{content:'▶ ';font-size:.7rem}
.section{transition:max-height .3s ease}
.section.hidden{display:none}
.subtitle{color:var(--text-muted);font-size:.9rem;margin-bottom:2rem}

/* Cards */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:1.5rem 0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.2rem;transition:border-color .2s}
.card:hover{border-color:var(--accent)}
.card-label{font-size:.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em}
.card-value{font-size:1.6rem;font-weight:700;margin-top:.3rem}

/* Risk gauge */
.risk-gauge{text-align:center;padding:1.5rem}
.risk-ring{width:120px;height:120px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 auto;font-size:2.2rem;font-weight:800;transition:border-color .3s}
.risk-label{font-size:.85rem;font-weight:600;margin-top:.2rem}

/* Severity badges */
.sev-badge{display:inline-block;padding:.15rem .6rem;border-radius:4px;font-size:.8rem;font-weight:600;text-transform:uppercase}
.sev-critical{background:rgba(220,38,38,.15);color:var(--sev-crit)}
.sev-high{background:rgba(234,88,12,.15);color:var(--sev-high)}
.sev-medium{background:rgba(202,138,4,.15);color:var(--sev-med)}
.sev-low{background:rgba(8,145,178,.15);color:var(--sev-low)}
.sev-info{background:rgba(107,114,128,.15);color:var(--sev-info)}

/* Severity count cards */
.sev-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;margin:1rem 0}
.sev-card{text-align:center;padding:.8rem;border-radius:var(--radius);background:var(--surface);border:1px solid var(--border)}
.sev-card .count{font-size:1.8rem;font-weight:800}
.sev-card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}

/* Tables */
table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:var(--radius);overflow:hidden;margin:1rem 0}
th{background:var(--card);color:var(--accent);text-align:left;padding:.7rem 1rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;position:sticky;top:0}
td{padding:.55rem 1rem;border-bottom:1px solid rgba(255,255,255,.04);font-size:.88rem}
tr:hover{background:rgba(59,130,246,.04)}
td a{color:var(--accent);text-decoration:none}
td a:hover{text-decoration:underline}
td code{font-family:var(--mono);font-size:.85rem;background:var(--card);padding:.1rem .4rem;border-radius:3px}

/* Search/filter bar */
.filter-bar{display:flex;gap:.8rem;margin:1rem 0;flex-wrap:wrap;align-items:center}
.filter-bar input{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:.5rem .8rem;border-radius:var(--radius);font-size:.88rem;flex:1;min-width:200px}
.filter-bar input:focus{outline:none;border-color:var(--accent)}
.filter-bar select{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:.5rem;border-radius:var(--radius);font-size:.85rem}

/* Footer */
.footer{text-align:center;color:var(--text-muted);font-size:.8rem;margin-top:3rem;padding:1.5rem 0;border-top:1px solid var(--border)}
.footer a{color:var(--accent);text-decoration:none}

/* System info table */
.sys-table{max-width:600px}
.sys-table td:first-child{font-weight:600;color:var(--text-sec);width:180px}
</style>
</head>
<body>
<nav>
  <span class="brand">IntrusionInspector</span>
  <a href="#summary">Summary</a>
  <a href="#mitre">MITRE</a>
  <a href="#findings">Findings</a>
  <a href="#system">System</a>
  <a href="#collectors">Collectors</a>
  <a href="#timeline">Timeline</a>
  <a href="#" onclick="toggleAll();return false">Toggle All</a>
</nav>
<div class="container">
HTMLEOF

    # Part 2: Dynamic content with bash variable interpolation
    cat >> "$html_file" <<EOF

<h1>IntrusionInspector Report</h1>
<p class="subtitle">
  Generated $(utc_now) &nbsp;|&nbsp; v${VERSION}
  $( [[ -n "$case_id" ]] && echo "&nbsp;|&nbsp; Case: <strong>${case_id}</strong>" )
  $( [[ -n "$examiner" ]] && echo "&nbsp;|&nbsp; Examiner: <strong>${examiner}</strong>" )
</p>

<!-- ═══════════ Executive Summary ═══════════ -->
<div id="summary">
<div class="grid">
  <div class="card"><div class="card-label">Hostname</div><div class="card-value">${hostname_val:-—}</div></div>
  <div class="card"><div class="card-label">Operating System</div><div class="card-value">${os_val:-—} ${os_version}</div></div>
  <div class="card"><div class="card-label">Architecture</div><div class="card-value">${arch_val:-—}</div></div>
  <div class="card"><div class="card-label">Kernel</div><div class="card-value">${kernel_val:-—}</div></div>
</div>

<div class="grid">
  <div class="card risk-gauge">
    <div class="card-label">Risk Score</div>
    <div class="risk-ring" style="border:5px solid ${risk_color}">${risk_score:-0}</div>
    <div class="risk-label" style="color:${risk_color}">${risk_label}</div>
    <div style="color:var(--text-muted);font-size:.75rem;margin-top:.3rem">out of ${MAX_RISK_SCORE}</div>
  </div>
  <div class="card"><div class="card-label">Total Findings</div><div class="card-value">${finding_count}</div></div>
  <div class="card"><div class="card-label">MITRE Techniques</div><div class="card-value">${technique_count:-0}</div></div>
  <div class="card"><div class="card-label">Total Artifacts</div><div class="card-value">${total_artifacts}</div></div>
</div>

<div class="sev-grid">
  <div class="sev-card"><div class="count sev-critical">${count_critical}</div><div class="label">Critical</div></div>
  <div class="sev-card"><div class="count sev-high">${count_high}</div><div class="label">High</div></div>
  <div class="sev-card"><div class="count sev-medium">${count_medium}</div><div class="label">Medium</div></div>
  <div class="sev-card"><div class="count sev-low">${count_low}</div><div class="label">Low</div></div>
  <div class="sev-card"><div class="count sev-info">${count_info}</div><div class="label">Info</div></div>
</div>
</div>

<!-- ═══════════ MITRE ATT&CK ═══════════ -->
<h2 id="mitre" onclick="toggleSection('mitre-section')">MITRE ATT&CK Coverage</h2>
<div id="mitre-section" class="section">
<table>
<thead><tr><th>Technique</th><th>Tactic</th><th>Count</th><th>Reference</th></tr></thead>
<tbody>
${mitre_rows:-<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No techniques detected</td></tr>}
</tbody>
</table>
</div>

<!-- ═══════════ Findings ═══════════ -->
<h2 id="findings" onclick="toggleSection('findings-section')">Findings (${finding_count})</h2>
<div id="findings-section" class="section">
<div class="filter-bar">
  <input type="text" id="findingsSearch" placeholder="Search findings..." onkeyup="filterFindings()">
  <select id="severityFilter" onchange="filterFindings()">
    <option value="">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
</div>
<table id="findingsTable">
<thead><tr><th>#</th><th>Severity</th><th>Description</th><th>MITRE</th><th>Source</th></tr></thead>
<tbody>
${findings_rows:-<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No findings</td></tr>}
</tbody>
</table>
</div>

<!-- ═══════════ System Overview ═══════════ -->
<h2 id="system" onclick="toggleSection('system-section')">System Overview</h2>
<div id="system-section" class="section">
<table class="sys-table">
<tbody>
<tr><td>Hostname</td><td>${hostname_val:-—}</td></tr>
<tr><td>OS</td><td>${os_val:-—} ${os_version}</td></tr>
<tr><td>Architecture</td><td>${arch_val:-—}</td></tr>
<tr><td>Kernel</td><td>${kernel_val:-—}</td></tr>
<tr><td>CPU</td><td>${cpu_model:-—}</td></tr>
<tr><td>RAM</td><td>${ram_mb:-—} MB</td></tr>
<tr><td>Boot Time</td><td>${boot_time:-—}</td></tr>
<tr><td>Uptime</td><td>${uptime_sec:-—} seconds</td></tr>
<tr><td>Collection Start</td><td>${collection_start:-—}</td></tr>
<tr><td>Collection End</td><td>${collection_end:-—}</td></tr>
</tbody>
</table>
</div>

<!-- ═══════════ Collectors ═══════════ -->
<h2 id="collectors" onclick="toggleSection('collectors-section')">Collection Summary</h2>
<div id="collectors-section" class="section">
<table>
<thead><tr><th>Collector</th><th>Artifacts</th><th>Duration</th></tr></thead>
<tbody>
${collector_rows:-<tr><td colspan="3" style="text-align:center;color:var(--text-muted)">No data</td></tr>}
</tbody>
</table>
</div>

<!-- ═══════════ Timeline ═══════════ -->
<h2 id="timeline" onclick="toggleSection('timeline-section')">Timeline</h2>
<div id="timeline-section" class="section">
<div class="filter-bar">
  <input type="text" id="timelineSearch" placeholder="Search timeline..." onkeyup="filterTimeline()">
</div>
<table id="timelineTable">
<thead><tr><th>Timestamp</th><th>Source</th><th>Type</th></tr></thead>
<tbody>
${timeline_rows:-<tr><td colspan="3" style="text-align:center;color:var(--text-muted)">No timeline data</td></tr>}
</tbody>
</table>
</div>

<div class="footer">
  <strong>IntrusionInspector</strong> v${VERSION} — Bash DFIR Triage Tool<br>
  $( [[ -n "$examiner" ]] && echo "Examiner: ${examiner} &nbsp;|&nbsp;" )
  $( [[ -n "$case_id" ]] && echo "Case: ${case_id} &nbsp;|&nbsp;" )
  Report generated $(utc_now)
</div>
</div>
EOF

    # Part 3: JavaScript for interactivity (quoted heredoc — no expansion needed)
    cat >> "$html_file" <<'JSEOF'
<script>
function toggleSection(id){
  var s=document.getElementById(id);
  if(s){s.classList.toggle('hidden')}
  var h=s?s.previousElementSibling:null;
  if(h&&h.tagName==='H2'){h.classList.toggle('collapsed')}
}
function toggleAll(){
  var sections=document.querySelectorAll('.section');
  var allHidden=true;
  sections.forEach(function(s){if(!s.classList.contains('hidden'))allHidden=false});
  sections.forEach(function(s){
    if(allHidden){s.classList.remove('hidden')}else{s.classList.add('hidden')}
  });
  document.querySelectorAll('h2[onclick]').forEach(function(h){
    if(allHidden){h.classList.remove('collapsed')}else{h.classList.add('collapsed')}
  });
}
function filterFindings(){
  var q=(document.getElementById('findingsSearch').value||'').toLowerCase();
  var sev=document.getElementById('severityFilter').value;
  var rows=document.querySelectorAll('#findingsTable .finding-row');
  rows.forEach(function(r){
    var text=r.textContent.toLowerCase();
    var matchText=!q||text.indexOf(q)>=0;
    var matchSev=!sev||r.getAttribute('data-severity')===sev;
    r.style.display=(matchText&&matchSev)?'':'none';
  });
}
function filterTimeline(){
  var q=(document.getElementById('timelineSearch').value||'').toLowerCase();
  var rows=document.querySelectorAll('#timelineTable .timeline-row');
  rows.forEach(function(r){
    r.style.display=(!q||r.textContent.toLowerCase().indexOf(q)>=0)?'':'none';
  });
}
</script>
</body>
</html>
JSEOF

    log_info "HTML report written to ${html_file}"
}
