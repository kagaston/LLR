#!/usr/bin/env bash
##############################################################################
# logging.sh — Structured Logging & Audit Trail
##############################################################################
#
# Part of IntrusionInspector (Bash Edition), a DFIR triage toolkit.
#
# PURPOSE:
#   Provides two distinct logging channels:
#     1. Console logging — colored, human-readable output to stderr for the
#        examiner running the tool interactively.
#     2. Audit logging — machine-readable JSON Lines (one JSON object per
#        line) appended to an audit.log file that documents every action
#        the tool performed, for chain-of-custody and reproducibility.
#
# ARCHITECTURAL ROLE:
#   Nearly every module sources logging.sh. It depends on json.sh (for
#   json_escape in audit_log) and has no other internal dependencies.
#   Console output goes to stderr so it never contaminates stdout, which
#   collectors may use for data piping.
#
# DESIGN DECISIONS:
#   - All console output is written to stderr (>&2) so that stdout remains
#     available for structured data pipelines between collectors.
#   - ANSI color codes are hardcoded rather than queried via tput because
#     tput requires a valid TERM (which may not be set in chroot or SSH
#     sessions during incident response). The escape sequences used here
#     work on every terminal emulator we target.
#   - Log levels use a numeric mapping (DEBUG=0, INFO=1, WARN=2, ERROR=3)
#     to allow simple integer comparison. The LOG_LEVEL env var controls
#     the minimum severity that reaches the console.
#   - The audit log uses JSON Lines format (newline-delimited JSON) rather
#     than a single JSON array so that entries can be safely appended
#     without reading/rewriting the entire file — important when the tool
#     crashes mid-run and partial output must still be parseable.
#
# EXPORTED GLOBALS:
#   LOG_LEVEL       — minimum console log level (default: "INFO")
#   VERBOSE         — verbose mode flag (default: "false")
#   AUDIT_LOG_FILE  — path to the audit log; empty until audit_init is called
#
# FUNCTIONS:
#   _log_level_num  — (internal) map level name to numeric priority
#   _should_log     — (internal) check if a message meets the threshold
#   log_msg         — core console log function
#   log_debug, log_info, log_warn, log_error — convenience wrappers
#   log_status      — print a status line with a Unicode icon
#   log_success, log_fail, log_step — semantic status shortcuts
#   log_banner      — print a section-separator banner
#   audit_init      — initialise the audit log file
#   audit_log       — append a structured event to the audit log
#
##############################################################################

# -------------------------------------------------------------------
# Source guard.
# -------------------------------------------------------------------
_LOGGING_LOADED=${_LOGGING_LOADED:-false}
[[ "$_LOGGING_LOADED" == "true" ]] && return 0
_LOGGING_LOADED=true

# -------------------------------------------------------------------
# ANSI color constants.
# Prefixed with underscore to signal "module-private". Using raw escape
# sequences instead of tput for reliability in minimal/chroot environments
# where terminfo databases may be missing.
# -------------------------------------------------------------------
_CLR_RESET='\033[0m'
_CLR_RED='\033[0;31m'
_CLR_GREEN='\033[0;32m'
_CLR_YELLOW='\033[0;33m'
_CLR_BLUE='\033[0;34m'
_CLR_CYAN='\033[0;36m'
_CLR_BOLD='\033[1m'
_CLR_DIM='\033[2m'

# -------------------------------------------------------------------
# Runtime log configuration.
# LOG_LEVEL can be overridden via environment variable before sourcing.
# VERBOSE enables extra detail in some collectors (not used by this
# module directly, but declared here as the canonical location).
# -------------------------------------------------------------------
LOG_LEVEL="${LOG_LEVEL:-INFO}"
VERBOSE="${VERBOSE:-false}"

# Map a log level name to a numeric priority for comparison.
# Lower numbers = more verbose. Unknown levels default to INFO (1).
# Args:
#   $1 — level name: "DEBUG", "INFO", "WARN", or "ERROR"
# Returns: prints the numeric priority to stdout.
_log_level_num() {
    case "$1" in
        DEBUG) echo 0 ;;
        INFO)  echo 1 ;;
        WARN)  echo 2 ;;
        ERROR) echo 3 ;;
        *)     echo 1 ;;
    esac
}

# Determine whether a message at the given level should be emitted.
# Compares the message's numeric level against the configured LOG_LEVEL.
# Args:
#   $1 — the message's level name
# Returns: 0 (true) if the message should be logged, 1 (false) to suppress.
_should_log() {
    local msg_level="$1"
    local current="$(_log_level_num "$LOG_LEVEL")"
    local requested="$(_log_level_num "$msg_level")"
    [[ "$requested" -ge "$current" ]]
}

# Core console logging function.
# Formats a timestamped, color-coded log line and writes it to stderr.
# The timestamp is UTC (%-less format) to avoid timezone ambiguity in IR.
# The level field is left-padded to 5 chars for alignment (e.g., "INFO ").
#
# Args:
#   $1    — log level ("DEBUG", "INFO", "WARN", "ERROR")
#   $2... — message text (all remaining arguments are joined with spaces)
# Output: writes to stderr; produces nothing on stdout.
log_msg() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date -u '+%H:%M:%S')"

    _should_log "$level" || return 0

    local color
    case "$level" in
        DEBUG) color="$_CLR_DIM" ;;
        INFO)  color="$_CLR_BLUE" ;;
        WARN)  color="$_CLR_YELLOW" ;;
        ERROR) color="$_CLR_RED" ;;
        *)     color="$_CLR_RESET" ;;
    esac

    printf '%b[%s]%b %b%-5s%b %s\n' \
        "$_CLR_DIM" "$ts" "$_CLR_RESET" \
        "$color" "$level" "$_CLR_RESET" \
        "$msg" >&2
}

# Convenience wrappers that fix the log level, so callers don't need to
# remember the level name strings.
# Args:
#   $@ — message text forwarded to log_msg
log_debug() { log_msg "DEBUG" "$@"; }
log_info()  { log_msg "INFO"  "$@"; }
log_warn()  { log_msg "WARN"  "$@"; }
log_error() { log_msg "ERROR" "$@"; }

# Print a status line with a leading Unicode icon in bold.
# Used for progress reporting during collection (✓ success, ✗ failure, → step).
# Args:
#   $1    — the icon character (e.g., "✓", "✗", "→")
#   $2... — status message text
# Output: writes to stderr.
log_status() {
    local icon="$1"
    shift
    printf '%b%s%b %s\n' "$_CLR_BOLD" "$icon" "$_CLR_RESET" "$*" >&2
}

# Semantic status helpers — each binds a specific icon to log_status.
# Args:
#   $@ — message text forwarded to log_status
log_success() { log_status "✓" "$@"; }
log_fail()    { log_status "✗" "$@"; }
log_step()    { log_status "→" "$@"; }

# Print a horizontal-rule banner for visual section separation.
# Uses Unicode box-drawing character ─ (U+2500) repeated to 60 columns.
# The `seq` + `printf '%.0s─'` idiom is Bash 3.x safe (no {1..N} brace
# expansion with variables, which doesn't work in Bash 3.x).
# Args:
#   $1 — the section title text
# Output: writes to stderr.
log_banner() {
    local msg="$1"
    local width=60
    printf '\n%b' "$_CLR_CYAN" >&2
    printf '%.0s─' $(seq 1 "$width") >&2
    printf '\n  %s\n' "$msg" >&2
    printf '%.0s─' $(seq 1 "$width") >&2
    printf '%b\n\n' "$_CLR_RESET" >&2
}

# -------------------------------------------------------------------
# Audit log — machine-readable chain-of-custody record.
#
# The audit log captures timestamped events (collector start/stop,
# errors, file accesses) in JSON Lines format. This file is included
# in the final output archive so reviewers can verify exactly what
# the tool did and when.
# -------------------------------------------------------------------
AUDIT_LOG_FILE=""

# Initialise the audit log file in the given output directory.
# Creates (or truncates) the audit.log file and writes the first event.
# Must be called once before any audit_log calls; if skipped, audit_log
# silently no-ops (by checking AUDIT_LOG_FILE is non-empty).
# Args:
#   $1 — the output directory path (e.g., "./output/case-12345")
audit_init() {
    AUDIT_LOG_FILE="${1}/audit.log"
    : > "$AUDIT_LOG_FILE"
    audit_log "audit_start" "Audit log initialized"
}

# Append a structured event to the audit log file.
# Each line is a self-contained JSON object with timestamp, event type,
# and detail string. Uses json_escape (from json.sh) to sanitise the
# event and detail fields against injection of special characters.
#
# Silently returns if audit_init has not been called (AUDIT_LOG_FILE is
# empty), which allows modules to be tested in isolation.
#
# Args:
#   $1 — event type identifier (e.g., "collector_start", "error")
#   $2 — human-readable detail string
audit_log() {
    [[ -z "$AUDIT_LOG_FILE" ]] && return 0
    local event="$1"
    local detail="$2"
    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '{"timestamp": "%s", "event": "%s", "detail": "%s"}\n' \
        "$ts" "$(json_escape "$event")" "$(json_escape "$detail")" >> "$AUDIT_LOG_FILE"
}
