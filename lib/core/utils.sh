#!/usr/bin/env bash
##############################################################################
# utils.sh — Shared Utility Functions for Collectors and Analysis
##############################################################################
#
# Part of IntrusionInspector (Bash Edition), a DFIR triage toolkit.
#
# PURPOSE:
#   Provides high-level helper functions used across multiple collectors
#   and the analysis engine. This is the "Swiss army knife" module —
#   things that don't belong in platform/json/logging/config but are
#   needed in more than one place.
#
# ARCHITECTURAL ROLE:
#   Sits above the other core modules in the dependency graph. Depends on:
#     - platform.sh  (is_linux, is_darwin, has_cmd, file_size, compute_sha256, utc_now)
#     - json.sh      (json_object, json_kvs, json_kvn, json_kv, json_write)
#     - logging.sh   (log_debug, audit_log)
#     - config.sh    (MAX_FILE_HASH_SIZE, PLATFORM_LOWER)
#   Every collector module sources utils.sh as its single entry point
#   (utils.sh sources the others via the main loader).
#
# DESIGN DECISIONS:
#   - run_cmd and run_cmd_timeout suppress stderr (2>/dev/null) because
#     forensic commands may emit permission-denied warnings when run
#     without full root privileges. We prefer silent degradation over
#     noisy output that obscures real findings.
#   - get_user_homes uses /etc/passwd on Linux (works without LDAP/SSSD)
#     and `dscl` on macOS (the only reliable way to enumerate local
#     users on Darwin). Service accounts with /nologin or /false shells
#     are excluded since they rarely have forensically interesting homes.
#   - resolve_path manually walks symlinks on macOS because BSD readlink
#     lacks the `-f` (canonicalize) flag that GNU readlink provides.
#
# BASH 3.x COMPATIBILITY:
#   All functions use only indexed arrays, string operations, and
#   features available in Bash 3.2+. No nameref, no associative arrays,
#   no ${var,,} lowercasing.
#
# FUNCTIONS:
#   ensure_dir             — create a directory if it doesn't exist
#   run_cmd                — run a command if it exists, else log and fail
#   run_cmd_timeout        — run a command with a timeout (cross-platform)
#   hash_file              — SHA-256 hash a file if under size limit
#   collector_output       — build a standard collector result JSON object
#   write_collector_result — persist collector JSON and log completion
#   get_user_homes         — enumerate real user home directories
#   count_json_elements    — count elements in a JSON array string
#   safe_read_file         — read a file with a byte-count cap
#   in_array               — linear search for a value in an array
#   resolve_path           — portable readlink -f equivalent
#
##############################################################################

# -------------------------------------------------------------------
# Source guard.
# -------------------------------------------------------------------
_UTILS_LOADED=${_UTILS_LOADED:-false}
[[ "$_UTILS_LOADED" == "true" ]] && return 0
_UTILS_LOADED=true

# Create a directory (and parents) if it doesn't already exist.
# Uses -p so intermediate directories are created automatically.
# Silently succeeds if the directory already exists.
# Args:
#   $1 — directory path to create
ensure_dir() {
    [[ -d "$1" ]] || mkdir -p "$1"
}

# Run a command only if it is available in PATH, suppressing stderr.
# Returns the command's exit code on success, or 1 if the command is not
# found (with a DEBUG-level log message for diagnostics). This pattern
# lets collectors attempt optional commands without crashing when a tool
# isn't installed on a particular system.
# Args:
#   $1    — command name
#   $2... — arguments to pass to the command
# Returns: the command's exit status, or 1 if not found.
run_cmd() {
    local cmd="$1"
    shift
    if has_cmd "$cmd"; then
        "$cmd" "$@" 2>/dev/null
        return $?
    else
        log_debug "Command not found: $cmd"
        return 1
    fi
}

# Run a command with a timeout to prevent hangs during triage.
# Forensic commands can block indefinitely on NFS-mounted or damaged
# filesystems. This wrapper applies a time limit using the best
# available mechanism:
#   1. GNU `timeout` (Linux, Homebrew coreutils)
#   2. `gtimeout` (Homebrew name on macOS for GNU timeout)
#   3. Perl `alarm` (fallback — Perl ships with macOS and most Linux)
#   4. Direct execution with no timeout (last resort)
#
# Stderr is suppressed on all paths for consistency with run_cmd.
#
# Args:
#   $1    — timeout in seconds
#   $2... — command and arguments to execute
# Returns: the command's exit status, or 124 on timeout (GNU timeout convention).
run_cmd_timeout() {
    local timeout_sec="$1"
    shift
    if has_cmd timeout; then
        timeout "$timeout_sec" "$@" 2>/dev/null
    elif has_cmd gtimeout; then
        gtimeout "$timeout_sec" "$@" 2>/dev/null
    elif has_cmd perl; then
        perl -e "alarm $timeout_sec; exec @ARGV" -- "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
}

# Compute the SHA-256 hash of a file, but only if it's under the
# configured size limit (MAX_FILE_HASH_SIZE from config.sh).
# Hashing very large files (e.g., database dumps, core dumps) during
# triage is wasteful and can stall collection. Files over the limit
# are skipped with a debug log entry.
# Args:
#   $1 — path to the file
# Returns: prints the 64-character hex SHA-256 digest, or returns 1 if
#          the file is missing, unreadable, or over the size limit.
hash_file() {
    local file="$1"
    local size
    size="$(file_size "$file" 2>/dev/null)" || return 1
    if [[ "$size" -gt "$MAX_FILE_HASH_SIZE" ]]; then
        log_debug "Skipping hash for $file (${size} bytes > limit)"
        return 1
    fi
    compute_sha256 "$file"
}

# Build a standardised JSON wrapper around a collector's artifact array.
# Every collector produces output in this uniform envelope so the
# analysis engine and report generator can process all collectors
# identically. The envelope includes provenance metadata (hostname,
# platform, timing) alongside the actual artifacts.
#
# Args:
#   $1 — collector name (e.g., "network", "processes", "persistence")
#   $2 — pre-built JSON array string containing the collected artifacts
#   $3 — integer count of artifacts collected
#   $4 — collection start time as Unix epoch
#   $5 — collection end time as Unix epoch
# Returns: prints the complete JSON object to stdout.
collector_output() {
    local collector_name="$1"
    local artifacts_json="$2"
    local artifact_count="$3"
    local start_epoch="$4"
    local end_epoch="$5"
    local duration=$(( end_epoch - start_epoch ))

    json_object \
        "$(json_kvs "collector_name" "$collector_name")" \
        "$(json_kvs "platform" "$PLATFORM_LOWER")" \
        "$(json_kvs "hostname" "$(hostname)")" \
        "$(json_kvs "collected_at" "$(utc_now)")" \
        "$(json_kvn "duration_seconds" "$duration")" \
        "$(json_kvn "artifact_count" "$artifact_count")" \
        "$(json_kv "artifacts" "$artifacts_json")"
}

# Persist a collector's JSON output to the raw/ subdirectory and record
# completion in the audit log. Each collector gets its own file
# (e.g., raw/network.json) for easy inspection and selective re-analysis.
# Args:
#   $1 — base output directory path
#   $2 — collector name (used as the filename stem)
#   $3 — the JSON content string to write
write_collector_result() {
    local output_dir="$1"
    local collector_name="$2"
    local json_content="$3"

    ensure_dir "${output_dir}/raw"
    json_write "${output_dir}/raw/${collector_name}.json" "$json_content"
    audit_log "collector_complete" "Collector ${collector_name} finished"
}

# Enumerate home directories for real (non-service) user accounts.
# This is a critical function because many artifacts (shell history,
# browser history, SSH keys, crontabs) live under user home dirs.
#
# Linux: Parses /etc/passwd for UIDs >= 1000 (normal users on systemd
#   distros) with interactive shells (not /nologin or /false). Also
#   always includes /root since root's UID is 0 (below the threshold).
#
# macOS: Uses Directory Services CLI (dscl) which is the canonical
#   interface to the local user directory. Skips system accounts whose
#   names start with underscore (Apple convention for service accounts).
#   Verifies each home directory actually exists on disk before emitting.
#
# Returns: prints one home directory path per line to stdout.
get_user_homes() {
    if is_linux; then
        awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $6}' /etc/passwd 2>/dev/null
        echo "/root"
    elif is_darwin; then
        dscl . list /Users 2>/dev/null | while read -r user; do
            [[ "$user" == _* ]] && continue
            local home
            home="$(dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
            [[ -d "$home" ]] && echo "$home"
        done
    fi
}

# Count the number of elements in a JSON array string.
# Uses jq if available for accuracy; otherwise falls back to a heuristic
# that counts double-quote characters and divides by 2 (works for arrays
# of simple string values, which covers most collector output).
# The fallback is intentionally approximate — it's only used for progress
# reporting, not for logic that requires precision.
# Args:
#   $1 — a JSON array string
# Returns: prints the element count as an integer to stdout.
count_json_elements() {
    local arr="$1"
    if command -v jq &>/dev/null; then
        printf '%s' "$arr" | jq 'length' 2>/dev/null || echo 0
    else
        local count
        count="$(printf '%s' "$arr" | grep -c '"' 2>/dev/null || true)"
        echo $(( count / 2 ))
    fi
}

# Read a file with a byte-count safety cap to prevent loading enormous
# files into memory. Defaults to 1 MB. Returns non-zero if the file
# doesn't exist or isn't readable, which lets callers use the pattern:
#   content="$(safe_read_file "$path")" || continue
# Args:
#   $1 — path to the file
#   $2 — (optional) maximum bytes to read; defaults to 1048576 (1 MB)
# Returns: prints the file content (truncated) to stdout, or returns 1.
safe_read_file() {
    local file="$1"
    local max_bytes="${2:-1048576}"  # 1MB default
    [[ -f "$file" && -r "$file" ]] || return 1
    head -c "$max_bytes" "$file" 2>/dev/null
}

# Check whether a value exists in an array (linear search).
# Bash 3.x has no built-in set/dict membership test, so this iterates
# the full list. Performance is acceptable because the arrays in this
# project (LOLBins, ports, env vars) are at most ~50 elements.
# Args:
#   $1    — the value to search for (needle)
#   $2... — the array elements to search through (haystack)
# Returns: 0 if found, 1 if not.
in_array() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

# Resolve a file path to its absolute, symlink-free canonical form.
# Equivalent to GNU `readlink -f`, which is not available on macOS
# (BSD readlink only supports `-n` and bare readlink for one hop).
#
# The macOS fallback manually walks the symlink chain: it cd's into
# each directory component and follows links until it reaches a real
# file, then reconstructs the absolute path with `pwd -P`.
#
# Note: the cd operations happen in the current shell (no subshell),
# but callers typically capture output via $(), which runs in a
# subshell anyway, so the working directory is not affected.
#
# Args:
#   $1 — the file path to resolve
# Returns: prints the canonical absolute path to stdout, or returns 1
#          if the path doesn't exist.
resolve_path() {
    if is_linux; then
        readlink -f "$1" 2>/dev/null
    else
        local target="$1"
        cd "$(dirname "$target")" 2>/dev/null || return 1
        target="$(basename "$target")"
        while [[ -L "$target" ]]; do
            target="$(readlink "$target")"
            cd "$(dirname "$target")" 2>/dev/null || return 1
            target="$(basename "$target")"
        done
        echo "$(pwd -P)/$target"
    fi
}
