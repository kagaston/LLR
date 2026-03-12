#!/usr/bin/env bash
# =============================================================================
# intrusion-inspector.sh — Main CLI Entry Point
# =============================================================================
#
# IntrusionInspector (Bash Edition) — a portable DFIR triage tool for macOS
# and Linux endpoints. This script is the top-level command-line interface
# that users invoke directly. It provides five subcommands:
#
#   triage   — Full pipeline: collect + analyze + report (the common path)
#   collect  — Gather forensic artifacts from the live endpoint
#   analyze  — Run anomaly detection, IOC/Sigma/YARA scanning on artifacts
#   report   — Generate human-readable reports from analysis output
#   verify   — Re-check evidence integrity against the SHA-256 manifest
#
# Architecture:
#   This file handles ONLY argument parsing and dispatch. All real work is
#   delegated to engine.sh functions (engine_collect, engine_analyze, etc.).
#   The engine in turn sources collectors, analyzers, reporters, and evidence
#   modules, so by the time we reach the case/esac dispatch below, the full
#   function library is available.
#
# Design decisions:
#   - Uses case/shift argument parsing instead of getopt/getopts for maximum
#     portability across macOS (BSD) and Linux (GNU) without external deps.
#   - set -euo pipefail ensures early failure on unset variables or pipe errors.
#   - All output (usage, errors) goes to stderr so stdout stays clean for
#     machine-consumable output if needed.
#
# =============================================================================
set -euo pipefail

# Resolve the script's directory regardless of symlinks so that all relative
# source paths work correctly even when invoked via a symlink or from another
# working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source core libraries in dependency order:
#   platform.sh — OS detection (PLATFORM variable, command availability)
#   json.sh     — Pure-bash JSON builder helpers (json_object, json_kvs, etc.)
#   config.sh   — Default configuration constants (VERSION, MAX_RISK_SCORE, etc.)
#   logging.sh  — Logging primitives (log_info, log_error, log_banner, etc.)
#   utils.sh    — Utility functions (epoch_now, utc_now, ensure_dir, etc.)
#   engine.sh   — Orchestrator that sources all collectors/analyzers/reporters
source "${SCRIPT_DIR}/lib/core/platform.sh"
source "${SCRIPT_DIR}/lib/core/json.sh"
source "${SCRIPT_DIR}/lib/core/config.sh"
source "${SCRIPT_DIR}/lib/core/logging.sh"
source "${SCRIPT_DIR}/lib/core/utils.sh"
source "${SCRIPT_DIR}/lib/engine.sh"

# -----------------------------------------------------------------------------
# print_version — Display the tool version string
#
# Reads VERSION from config.sh. Printed to stdout for scripting compatibility
# (e.g., `intrusion-inspector --version` in CI pipelines).
# -----------------------------------------------------------------------------
print_version() {
    echo "intrusion-inspector ${VERSION}"
}

# -----------------------------------------------------------------------------
# print_usage — Display the top-level help text
#
# Shows available subcommands and global options. Output goes to stderr so it
# doesn't interfere with piped output.
# -----------------------------------------------------------------------------
print_usage() {
    cat >&2 <<EOF
intrusion-inspector v${VERSION} — DFIR collection and triage for endpoints

Usage:
  $(basename "$0") <command> [options]

Commands:
  triage    Full pipeline: collect + analyze + report
  collect   Collect forensic artifacts from the endpoint
  analyze   Analyze previously collected artifacts
  report    Generate reports from analysis results
  verify    Verify evidence integrity against manifest

Global Options:
  --verbose, -v       Enable debug logging
  --version           Show version
  --help, -h          Show this help

Run '$(basename "$0") <command> --help' for command-specific options.
EOF
}

# -----------------------------------------------------------------------------
# print_collect_usage — Help text for the "collect" subcommand
#
# The collect subcommand requires an output directory (-o) and supports
# optional profile selection and chain-of-custody metadata.
# -----------------------------------------------------------------------------
print_collect_usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") collect [options]

Options:
  -o, --output DIR       Output directory (required)
  -p, --profile NAME     Collection profile: quick, standard, full (default: standard)
  --case-id ID           Case identifier for chain of custody
  --examiner NAME        Examiner name for chain of custody
  -h, --help             Show this help
EOF
}

# -----------------------------------------------------------------------------
# print_analyze_usage — Help text for the "analyze" subcommand
#
# The analyze subcommand operates on a directory of previously collected
# artifacts and supports optional IOC, Sigma, and YARA rule paths.
# -----------------------------------------------------------------------------
print_analyze_usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") analyze [options]

Options:
  -i, --input DIR        Directory with collected artifacts (required)
  --iocs PATH            Path to IOC rules directory or file
  --sigma PATH           Path to Sigma rules directory or file
  --yara PATH            Path to YARA rules directory or file
  -h, --help             Show this help
EOF
}

# -----------------------------------------------------------------------------
# print_report_usage — Help text for the "report" subcommand
#
# The report subcommand reads analysis results and produces formatted output.
# Supports html, json, csv, and console formats (default: html).
# -----------------------------------------------------------------------------
print_report_usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") report [options]

Options:
  -i, --input DIR        Directory with analysis results (required)
  -f, --format FMT       Report format: html, json, csv, console (default: html)
  -h, --help             Show this help
EOF
}

# -----------------------------------------------------------------------------
# print_triage_usage — Help text for the "triage" subcommand
#
# Triage is the "do everything" command: collect + analyze + report in one
# invocation. It accepts the union of all collect/analyze/report options plus
# --secure-output for creating password-encrypted evidence packages.
# -----------------------------------------------------------------------------
print_triage_usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") triage [options]

Options:
  -o, --output DIR       Output directory (required)
  -p, --profile NAME     Collection profile: quick, standard, full (default: standard)
  --case-id ID           Case identifier
  --examiner NAME        Examiner name
  --iocs PATH            IOC rules path
  --sigma PATH           Sigma rules path
  --yara PATH            YARA rules path
  --secure-output        Create encrypted evidence package
  --password PASS        Password for encrypted package
  -f, --format FMT       Report format(s), comma-separated (default: html)
  -h, --help             Show this help
EOF
}

# -----------------------------------------------------------------------------
# print_verify_usage — Help text for the "verify" subcommand
#
# Verify re-hashes all evidence files and compares against the stored
# manifest.json to detect any post-collection tampering or corruption.
# -----------------------------------------------------------------------------
print_verify_usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") verify [options]

Options:
  -i, --input DIR        Directory to verify (required)
  -h, --help             Show this help
EOF
}

# =============================================================================
# Subcommand Dispatch
# =============================================================================
# Argument parsing uses a two-level case/shift pattern:
#   1. First argument is the subcommand (or a global flag like --version).
#   2. Each subcommand block has its own while/case loop for subcommand-specific
#      options, consuming arguments with shift.
#
# This avoids any dependency on getopt (GNU-only) or getopts (limited to
# single-char flags), keeping the tool fully portable across macOS and Linux.
# =============================================================================

# Bail with usage if invoked with no arguments
[[ $# -eq 0 ]] && { print_usage; exit 1; }

# Extract the subcommand and shift it off the argument list
COMMAND="$1"
shift

case "$COMMAND" in
    --version|-V)
        print_version
        exit 0
        ;;
    --help|-h)
        print_usage
        exit 0
        ;;

    # ── collect: Gather forensic artifacts from the endpoint ──
    collect)
        # Defaults pulled from config.sh constants
        OPT_OUTPUT=""
        OPT_PROFILE="$DEFAULT_PROFILE"
        OPT_CASE_ID="$CASE_ID"
        OPT_EXAMINER="$EXAMINER"

        # Parse collect-specific options via case/shift
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -o|--output)   OPT_OUTPUT="$2";   shift 2 ;;
                -p|--profile)  OPT_PROFILE="$2";  shift 2 ;;
                --case-id)     OPT_CASE_ID="$2";  shift 2 ;;
                --examiner)    OPT_EXAMINER="$2"; shift 2 ;;
                -h|--help)     print_collect_usage; exit 0 ;;
                *) log_error "Unknown option: $1"; print_collect_usage; exit 1 ;;
            esac
        done

        # Output directory is mandatory — no sensible default exists
        [[ -z "$OPT_OUTPUT" ]] && { log_error "Output directory is required (-o)"; exit 1; }

        engine_collect "$OPT_OUTPUT" "$OPT_PROFILE" "$OPT_CASE_ID" "$OPT_EXAMINER"
        ;;

    # ── analyze: Run analysis on previously collected artifacts ──
    analyze)
        # Rule paths are optional — analyzers that need them are skipped if empty
        OPT_INPUT=""
        OPT_IOCS=""
        OPT_SIGMA=""
        OPT_YARA=""

        while [[ $# -gt 0 ]]; do
            case "$1" in
                -i|--input)  OPT_INPUT="$2"; shift 2 ;;
                --iocs)      OPT_IOCS="$2";  shift 2 ;;
                --sigma)     OPT_SIGMA="$2"; shift 2 ;;
                --yara)      OPT_YARA="$2";  shift 2 ;;
                -h|--help)   print_analyze_usage; exit 0 ;;
                *) log_error "Unknown option: $1"; print_analyze_usage; exit 1 ;;
            esac
        done

        # Input must point to an existing collection directory
        [[ -z "$OPT_INPUT" ]] && { log_error "Input directory is required (-i)"; exit 1; }
        [[ -d "$OPT_INPUT" ]] || { log_error "Input directory does not exist: $OPT_INPUT"; exit 1; }

        engine_analyze "$OPT_INPUT" "$OPT_IOCS" "$OPT_SIGMA" "$OPT_YARA"
        ;;

    # ── report: Generate formatted reports from analysis results ──
    report)
        OPT_INPUT=""
        OPT_FORMAT="html"

        while [[ $# -gt 0 ]]; do
            case "$1" in
                -i|--input)   OPT_INPUT="$2";  shift 2 ;;
                -f|--format)  OPT_FORMAT="$2"; shift 2 ;;
                -h|--help)    print_report_usage; exit 0 ;;
                *) log_error "Unknown option: $1"; print_report_usage; exit 1 ;;
            esac
        done

        [[ -z "$OPT_INPUT" ]] && { log_error "Input directory is required (-i)"; exit 1; }
        [[ -d "$OPT_INPUT" ]] || { log_error "Input directory does not exist: $OPT_INPUT"; exit 1; }

        engine_report "$OPT_INPUT" "$OPT_FORMAT"
        ;;

    # ── triage: Full pipeline (collect + analyze + report) in one shot ──
    triage)
        # Triage accepts the union of collect + analyze + report options,
        # plus --secure-output / --password for encrypted evidence packaging.
        OPT_OUTPUT=""
        OPT_PROFILE="$DEFAULT_PROFILE"
        OPT_CASE_ID="$CASE_ID"
        OPT_EXAMINER="$EXAMINER"
        OPT_IOCS=""
        OPT_SIGMA=""
        OPT_YARA=""
        OPT_SECURE=false
        OPT_PASSWORD=""
        OPT_FORMATS="html"

        while [[ $# -gt 0 ]]; do
            case "$1" in
                -o|--output)       OPT_OUTPUT="$2";    shift 2 ;;
                -p|--profile)      OPT_PROFILE="$2";   shift 2 ;;
                --case-id)         OPT_CASE_ID="$2";   shift 2 ;;
                --examiner)        OPT_EXAMINER="$2";  shift 2 ;;
                --iocs)            OPT_IOCS="$2";      shift 2 ;;
                --sigma)           OPT_SIGMA="$2";     shift 2 ;;
                --yara)            OPT_YARA="$2";      shift 2 ;;
                --secure-output)   OPT_SECURE=true;    shift ;;
                --password)        OPT_PASSWORD="$2";  shift 2 ;;
                -f|--format)       OPT_FORMATS="$2";   shift 2 ;;
                -h|--help)         print_triage_usage;  exit 0 ;;
                *) log_error "Unknown option: $1"; print_triage_usage; exit 1 ;;
            esac
        done

        [[ -z "$OPT_OUTPUT" ]] && { log_error "Output directory is required (-o)"; exit 1; }

        # If --secure-output was requested but no password was given on the
        # command line, prompt interactively. read -rs hides the input.
        if [[ "$OPT_SECURE" == "true" && -z "$OPT_PASSWORD" ]]; then
            printf 'Evidence package password: ' >&2
            read -rs OPT_PASSWORD
            echo >&2
        fi

        engine_triage "$OPT_OUTPUT" "$OPT_PROFILE" "$OPT_CASE_ID" "$OPT_EXAMINER" \
                      "$OPT_IOCS" "$OPT_SIGMA" "$OPT_YARA" \
                      "$OPT_SECURE" "$OPT_PASSWORD" "$OPT_FORMATS"
        ;;

    # ── verify: Re-check evidence integrity against the SHA-256 manifest ──
    verify)
        OPT_INPUT=""

        while [[ $# -gt 0 ]]; do
            case "$1" in
                -i|--input)  OPT_INPUT="$2"; shift 2 ;;
                -h|--help)   print_verify_usage; exit 0 ;;
                *) log_error "Unknown option: $1"; print_verify_usage; exit 1 ;;
            esac
        done

        [[ -z "$OPT_INPUT" ]] && { log_error "Input directory is required (-i)"; exit 1; }
        [[ -d "$OPT_INPUT" ]] || { log_error "Input directory does not exist: $OPT_INPUT"; exit 1; }

        engine_verify "$OPT_INPUT"
        ;;

    # Catch-all for unrecognized subcommands
    *)
        log_error "Unknown command: $COMMAND"
        print_usage
        exit 1
        ;;
esac
