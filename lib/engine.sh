#!/usr/bin/env bash
# =============================================================================
# lib/engine.sh — Pipeline Orchestrator
# =============================================================================
#
# Central orchestration module for IntrusionInspector. This file is the glue
# between the CLI entry point (intrusion-inspector.sh) and the individual
# component modules (collectors, analyzers, reporters, evidence handlers).
#
# Responsibilities:
#   1. Source all component modules via glob-based auto-discovery so that new
#      collectors/analyzers/reporters are picked up automatically.
#   2. Load collection profiles (quick/standard/full) from profiles/*.conf.
#   3. Coordinate the pipeline phases: Collection → Analysis → Reporting.
#   4. Manage cross-cutting concerns: audit logging, chain of custody,
#      evidence manifests, and optional encrypted packaging.
#   5. Expose engine_* functions that the CLI dispatches to.
#
# Include guard:
#   Uses _ENGINE_LOADED to prevent double-sourcing when multiple code paths
#   source this file (e.g., direct use vs. sourced by tests).
#
# =============================================================================

# Include guard — prevent re-sourcing in complex source chains
_ENGINE_LOADED=${_ENGINE_LOADED:-false}
[[ "$_ENGINE_LOADED" == "true" ]] && return 0
_ENGINE_LOADED=true

# Auto-discover and source all component modules. Each glob loads every .sh
# file from its respective directory. The [[ -f ]] guard handles the case
# where a glob expands to a literal (no matching files).
for _collector_file in "${SCRIPT_DIR}"/lib/collectors/*.sh; do
    [[ -f "$_collector_file" ]] && source "$_collector_file"
done
for _analyzer_file in "${SCRIPT_DIR}"/lib/analyzers/*.sh; do
    [[ -f "$_analyzer_file" ]] && source "$_analyzer_file"
done
for _reporter_file in "${SCRIPT_DIR}"/lib/reporters/*.sh; do
    [[ -f "$_reporter_file" ]] && source "$_reporter_file"
done
for _evidence_file in "${SCRIPT_DIR}"/lib/evidence/*.sh; do
    [[ -f "$_evidence_file" ]] && source "$_evidence_file"
done

# -----------------------------------------------------------------------------
# load_profile — Load a named collection profile
#
# Parameters:
#   $1  profile_name — One of: quick, standard, full
#
# Profiles are plain bash files in profiles/*.conf that set:
#   PROFILE_NAME, PROFILE_DESCRIPTION, PROFILE_COLLECTORS (array),
#   PROFILE_YARA_SCAN (bool), and other profile-specific tunables.
#
# Sourcing the profile file brings those variables into the current shell
# scope where run_collectors and run_analyzers can reference them.
# -----------------------------------------------------------------------------
load_profile() {
    local profile_name="$1"
    local profile_file="${SCRIPT_DIR}/profiles/${profile_name}.conf"

    if [[ ! -f "$profile_file" ]]; then
        log_error "Profile not found: ${profile_name}"
        log_error "Available profiles: quick, standard, full"
        exit 1
    fi

    source "$profile_file"
    log_info "Loaded profile: ${PROFILE_NAME} — ${PROFILE_DESCRIPTION}"
}

# -----------------------------------------------------------------------------
# run_collectors — Execute every collector listed in the active profile
#
# Parameters:
#   $1  output_dir — Root output directory for this run
#
# Iterates over PROFILE_COLLECTORS (set by load_profile) and dynamically
# resolves each collector name to a function named collect_<name>. This
# convention-based dispatch lets new collectors be added by simply dropping
# a .sh file into lib/collectors/ that defines collect_<name>().
#
# Each collector receives the output_dir and is expected to write its
# artifacts under output_dir/raw/. Failures are logged but do not halt the
# pipeline — partial collection is preferred over no collection.
# -----------------------------------------------------------------------------
run_collectors() {
    local output_dir="$1"

    log_banner "Collection Phase"
    local total=${#PROFILE_COLLECTORS[@]}
    local idx=0
    local succeeded=0
    local failed=0

    for collector in "${PROFILE_COLLECTORS[@]}"; do
        idx=$((idx + 1))
        log_step "[$idx/$total] Running collector: ${collector}"

        # Convention: collector "foo" maps to function "collect_foo"
        local func_name="collect_${collector}"
        if declare -f "$func_name" &>/dev/null; then
            local start_ts
            start_ts="$(epoch_now)"

            if "$func_name" "$output_dir"; then
                succeeded=$((succeeded + 1))
                log_success "Collector ${collector} completed"
            else
                failed=$((failed + 1))
                log_warn "Collector ${collector} finished with errors"
            fi

            audit_log "collector_run" "${collector}: exit=$?"
        else
            log_warn "Collector function not found: ${func_name}"
            failed=$((failed + 1))
        fi
    done

    log_info "Collection complete: ${succeeded} succeeded, ${failed} failed out of ${total}"
}

# -----------------------------------------------------------------------------
# run_analyzers — Execute analysis modules on collected artifacts
#
# Parameters:
#   $1  output_dir — Root output directory containing raw/ artifacts
#   $2  iocs_path  — Path to IOC rules (file or directory), or "" to skip
#   $3  sigma_path — Path to Sigma rules (file or directory), or "" to skip
#   $4  yara_path  — Path to YARA rules (file or directory), or "" to skip
#
# Analyzers run in a fixed order:
#   1. Anomaly detection — always runs (baseline behavioral checks)
#   2. Timeline generation — always runs (chronological event ordering)
#   3. IOC scanning — only if iocs_path is non-empty
#   4. Sigma scanning — only if sigma_path is non-empty
#   5. YARA scanning — only if yara_path is non-empty AND profile enables it
#   6. MITRE ATT&CK mapping — always runs (maps findings to technique IDs)
#
# Unlike collectors (convention-based dispatch), analyzers are explicitly
# enumerated here because their execution order and conditional logic matter.
# Each analyzer writes results to output_dir/analysis/.
# -----------------------------------------------------------------------------
run_analyzers() {
    local output_dir="$1"
    local iocs_path="$2"
    local sigma_path="$3"
    local yara_path="$4"

    log_banner "Analysis Phase"
    ensure_dir "${output_dir}/analysis"

    # Anomaly detection runs unconditionally as the baseline analyzer
    log_step "Running anomaly detector"
    if declare -f analyze_anomalies &>/dev/null; then
        analyze_anomalies "$output_dir"
        audit_log "analyzer_run" "anomaly_detector"
    fi

    # Timeline sorts all timestamped events into chronological order
    log_step "Generating timeline"
    if declare -f analyze_timeline &>/dev/null; then
        analyze_timeline "$output_dir"
        audit_log "analyzer_run" "timeline"
    fi

    # IOC, Sigma, and YARA scanners are conditional on rule paths being provided
    if [[ -n "$iocs_path" ]]; then
        log_step "Running IOC scanner"
        if declare -f analyze_iocs &>/dev/null; then
            analyze_iocs "$output_dir" "$iocs_path"
            audit_log "analyzer_run" "ioc_scanner"
        fi
    fi

    if [[ -n "$sigma_path" ]]; then
        log_step "Running Sigma scanner"
        if declare -f analyze_sigma &>/dev/null; then
            analyze_sigma "$output_dir" "$sigma_path"
            audit_log "analyzer_run" "sigma_scanner"
        fi
    fi

    # YARA scanning additionally requires the profile to opt in via PROFILE_YARA_SCAN
    if [[ -n "$yara_path" && "$PROFILE_YARA_SCAN" == "true" ]]; then
        log_step "Running YARA scanner"
        if declare -f analyze_yara &>/dev/null; then
            analyze_yara "$output_dir" "$yara_path"
            audit_log "analyzer_run" "yara_scanner"
        fi
    fi

    # MITRE mapping runs last — it reads findings from other analyzers
    log_step "Mapping MITRE ATT&CK techniques"
    if declare -f analyze_mitre &>/dev/null; then
        analyze_mitre "$output_dir"
        audit_log "analyzer_run" "mitre_mapper"
    fi

    log_info "Analysis complete"
}

# -----------------------------------------------------------------------------
# run_reporters — Generate reports in one or more output formats
#
# Parameters:
#   $1  output_dir — Root output directory with analysis/ results
#   $2  formats    — Comma-separated list of formats (e.g., "html,json,csv")
#
# Like collectors, reporters use convention-based dispatch: format "html"
# resolves to function report_html(). Multiple formats can be requested
# in a single run by comma-separating them.
# -----------------------------------------------------------------------------
run_reporters() {
    local output_dir="$1"
    local formats="$2"

    log_banner "Reporting Phase"

    # Split comma-separated format list into an array
    IFS=',' read -ra format_list <<< "$formats"
    for fmt in "${format_list[@]}"; do
        # Strip whitespace for tolerance of "html, json" style input
        fmt="$(echo "$fmt" | tr -d ' ')"
        log_step "Generating ${fmt} report"

        local func_name="report_${fmt}"
        if declare -f "$func_name" &>/dev/null; then
            "$func_name" "$output_dir"
            audit_log "reporter_run" "${fmt}"
            log_success "Report generated: ${fmt}"
        else
            log_warn "Reporter not found: ${fmt}"
        fi
    done
}

# -----------------------------------------------------------------------------
# create_secure_package — Create a password-encrypted ZIP of all evidence
#
# Parameters:
#   $1  output_dir — Root output directory to package
#   $2  password   — Encryption password for the ZIP archive
#
# Produces output_dir.zip using the zip command's built-in AES encryption
# (-P flag). The subshell cd ensures the ZIP contains relative paths.
# Falls back gracefully if zip is not installed.
# -----------------------------------------------------------------------------
create_secure_package() {
    local output_dir="$1"
    local password="$2"

    log_step "Creating encrypted evidence package"

    local pkg_name="${output_dir}.zip"
    if has_cmd zip; then
        # cd into parent so ZIP paths are relative, not absolute
        (cd "$(dirname "$output_dir")" && zip -r -P "$password" "$(basename "$pkg_name")" "$(basename "$output_dir")" -q)
        log_success "Encrypted package: ${pkg_name}"
        audit_log "secure_package" "Created encrypted ZIP: ${pkg_name}"
    else
        log_warn "zip command not found — skipping secure output"
    fi
}

# =============================================================================
# Subcommand Implementations
# =============================================================================
# Each engine_* function is the top-level handler for one CLI subcommand.
# They are called from intrusion-inspector.sh after argument parsing.
# =============================================================================

# -----------------------------------------------------------------------------
# engine_collect — Collect forensic artifacts from the live endpoint
#
# Parameters:
#   $1  output_dir — Where to write collected artifacts
#   $2  profile    — Collection profile name (quick/standard/full)
#   $3  case_id    — Case identifier for chain of custody
#   $4  examiner   — Examiner name for chain of custody
#
# Pipeline: init → run_collectors → generate_manifest → finalize_custody
# Requires root because collectors need access to system logs, process
# tables, and privileged file paths.
# -----------------------------------------------------------------------------
engine_collect() {
    local output_dir="$1"
    local profile="$2"
    local case_id="$3"
    local examiner="$4"

    # Forensic collection requires root for access to system artifacts
    [[ "$EUID" -ne 0 ]] && { log_error "This tool must be run as root (current user: $(whoami))"; exit 1; }

    ensure_dir "$output_dir"
    load_profile "$profile"

    log_banner "IntrusionInspector v${VERSION} — Collecting Artifacts"
    log_info "Platform: ${PLATFORM} | Profile: ${profile} | Output: ${output_dir}"

    # Initialize audit trail and chain of custody before any data touches disk
    audit_init "$output_dir"
    init_chain_of_custody "$output_dir" "$case_id" "$examiner"

    local global_start
    global_start="$(epoch_now)"

    run_collectors "$output_dir"

    # Seal evidence: hash all files and record end timestamp
    generate_manifest "$output_dir"
    finalize_chain_of_custody "$output_dir"

    local global_end
    global_end="$(epoch_now)"
    local duration=$(( global_end - global_start ))

    log_info "Collection finished in ${duration}s"
    audit_log "collection_complete" "Duration: ${duration}s"
}

# -----------------------------------------------------------------------------
# engine_analyze — Run analysis on a directory of previously collected artifacts
#
# Parameters:
#   $1  input_dir  — Directory containing raw/ subdirectory with artifacts
#   $2  iocs_path  — Path to IOC rules, or "" to skip IOC scanning
#   $3  sigma_path — Path to Sigma rules, or "" to skip Sigma scanning
#   $4  yara_path  — Path to YARA rules, or "" to skip YARA scanning
#
# Can be run independently of collect (e.g., analyzing artifacts collected
# on another host). Defaults PROFILE_YARA_SCAN to false when run standalone
# since no profile has been loaded.
# -----------------------------------------------------------------------------
engine_analyze() {
    local input_dir="$1"
    local iocs_path="$2"
    local sigma_path="$3"
    local yara_path="$4"

    # Verify raw artifacts exist from a prior collection
    [[ -d "${input_dir}/raw" ]] || { log_error "No raw data found in ${input_dir}/raw/"; exit 1; }

    # Default YARA scanning off when running analyze standalone (no profile loaded)
    PROFILE_YARA_SCAN="${PROFILE_YARA_SCAN:-false}"

    # Ensure audit log path is set even when not preceded by engine_collect
    if [[ -z "$AUDIT_LOG_FILE" ]]; then
        AUDIT_LOG_FILE="${input_dir}/audit.log"
    fi

    log_banner "IntrusionInspector v${VERSION} — Analyzing Artifacts"

    run_analyzers "$input_dir" "$iocs_path" "$sigma_path" "$yara_path"
}

# -----------------------------------------------------------------------------
# engine_report — Generate reports from analysis results
#
# Parameters:
#   $1  input_dir — Directory containing analysis/ subdirectory
#   $2  formats   — Comma-separated report formats (html, json, csv, console)
#
# Can be run standalone against a directory that already has analysis results,
# allowing report regeneration without re-running collection or analysis.
# -----------------------------------------------------------------------------
engine_report() {
    local input_dir="$1"
    local formats="$2"

    if [[ -z "$AUDIT_LOG_FILE" ]]; then
        AUDIT_LOG_FILE="${input_dir}/audit.log"
    fi

    log_banner "IntrusionInspector v${VERSION} — Generating Reports"

    run_reporters "$input_dir" "$formats"
}

# -----------------------------------------------------------------------------
# engine_triage — Full pipeline: collect + analyze + report in one invocation
#
# Parameters:
#   $1  output_dir — Where to write all output
#   $2  profile    — Collection profile name (quick/standard/full)
#   $3  case_id    — Case identifier for chain of custody
#   $4  examiner   — Examiner name for chain of custody
#   $5  iocs_path  — Path to IOC rules, or "" to skip
#   $6  sigma_path — Path to Sigma rules, or "" to skip
#   $7  yara_path  — Path to YARA rules, or "" to skip
#   $8  secure     — "true" to create encrypted ZIP, "false" otherwise
#   $9  password   — Encryption password (only used when secure="true")
#   $10 formats    — Comma-separated report formats
#
# This is the most common invocation path for incident responders. It runs
# the full pipeline sequentially: collect → analyze → report → seal evidence.
# Optionally creates an encrypted evidence package at the end.
# -----------------------------------------------------------------------------
engine_triage() {
    local output_dir="$1"
    local profile="$2"
    local case_id="$3"
    local examiner="$4"
    local iocs_path="$5"
    local sigma_path="$6"
    local yara_path="$7"
    local secure="$8"
    local password="$9"
    local formats="${10}"

    [[ "$EUID" -ne 0 ]] && { log_error "This tool must be run as root (current user: $(whoami))"; exit 1; }

    ensure_dir "$output_dir"
    load_profile "$profile"

    log_banner "IntrusionInspector v${VERSION} — Full Triage"
    log_info "Platform: ${PLATFORM} | Profile: ${profile} | Output: ${output_dir}"

    audit_init "$output_dir"
    init_chain_of_custody "$output_dir" "$case_id" "$examiner"

    local global_start
    global_start="$(epoch_now)"

    # Execute the three pipeline phases in order
    run_collectors "$output_dir"
    run_analyzers "$output_dir" "$iocs_path" "$sigma_path" "$yara_path"
    run_reporters "$output_dir" "$formats"

    # Seal evidence after all phases complete
    generate_manifest "$output_dir"
    finalize_chain_of_custody "$output_dir"

    # Optionally package everything into a password-encrypted ZIP
    if [[ "$secure" == "true" ]]; then
        create_secure_package "$output_dir" "$password"
    fi

    local global_end
    global_end="$(epoch_now)"
    local duration=$(( global_end - global_start ))

    log_banner "Triage Complete"
    log_success "Output: ${output_dir}"
    log_info "Duration: ${duration}s"
    audit_log "triage_complete" "Duration: ${duration}s"
}

# -----------------------------------------------------------------------------
# engine_verify — Verify evidence integrity against the SHA-256 manifest
#
# Parameters:
#   $1  input_dir — Directory containing manifest.json and evidence files
#
# Delegates to verify_manifest() from lib/evidence/integrity.sh. This is a
# post-collection check used to confirm no files have been tampered with or
# corrupted since the manifest was generated.
# -----------------------------------------------------------------------------
engine_verify() {
    local input_dir="$1"

    log_banner "IntrusionInspector v${VERSION} — Verifying Evidence Integrity"

    if declare -f verify_manifest &>/dev/null; then
        verify_manifest "$input_dir"
    else
        log_error "Verification module not loaded"
        exit 1
    fi
}
