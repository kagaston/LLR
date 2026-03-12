#!/usr/bin/env bash
# ============================================================================
# Collector: environment
# ============================================================================
#
# Purpose:
#   Captures environment variables from the current process and per-user
#   sessions, flagging variables known to be suspicious or security-relevant.
#   Attackers commonly manipulate environment variables to hijack library
#   loading (LD_PRELOAD, DYLD_INSERT_LIBRARIES), modify program behavior
#   (HTTP_PROXY, HISTFILE=/dev/null), or establish persistence paths.
#
# Artifacts gathered:
#   Per variable: name, value, scope (current_process, user:<name>, or
#   launchctl), and a boolean "suspicious" flag indicating whether the
#   variable name matches the SUSPICIOUS_ENV_VARS watchlist.
#
# Platform support:
#   Both platforms:
#     - env command for current process environment variables
#   Linux:
#     - /proc/<pid>/environ for per-user environment snapshots.
#       Reads the environment of each user's oldest process (pgrep -u -o).
#       /proc environ files use null-byte delimiters, converted to newlines
#       with tr '\0' '\n'.
#   macOS:
#     - launchctl getenv for system-level environment variables.
#       macOS does not expose per-process environ through a pseudo-filesystem,
#       so only a fixed set of well-known variables (PATH, HOME, SHELL,
#       TMPDIR, USER, LOGNAME) are queried via launchctl.
#
# Suspicious variable detection:
#   The SUSPICIOUS_ENV_VARS array (defined in the profile/config) contains
#   variable names commonly abused by attackers, such as:
#     LD_PRELOAD, LD_LIBRARY_PATH, DYLD_INSERT_LIBRARIES, HTTP_PROXY,
#     HTTPS_PROXY, HISTFILE, HISTSIZE, etc.
#   The in_array helper function checks each variable name against this list.
#
# Output:
#   JSON array of environment variable artifacts, written via
#   write_collector_result.
# ============================================================================

# collect_environment — captures environment variables with suspicion flagging
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Current process environment (env command) is identical on both platforms.
#   Per-user environment differs significantly:
#     - Linux: reads /proc/<pid>/environ for each user's oldest process,
#       providing a complete snapshot of that user's environment
#     - macOS: queries launchctl for specific well-known variables since
#       /proc is not available and per-process environ access would require
#       parsing memory or using dtrace
collect_environment() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()

    # ── Current process environment ──
    # Captures the environment of the triage tool itself, which inherits
    # from the shell/session that launched it
    while IFS='=' read -r name value; do
        [[ -z "$name" ]] && continue
        local suspicious="false"
        if in_array "$name" "${SUSPICIOUS_ENV_VARS[@]}"; then
            suspicious="true"
        fi
        artifacts+=("$(json_object \
            "$(json_kvs "name" "$name")" \
            "$(json_kvs "value" "$value")" \
            "$(json_kvs "scope" "current_process")" \
            "$(json_kvb "suspicious" "$suspicious")"
        )")
    done < <(env 2>/dev/null | sort)

    if is_linux; then
        # ── Per-user environment from /proc ──
        # Each process has /proc/<pid>/environ containing its environment
        # as null-delimited key=value pairs. We read the oldest process
        # for each user (pgrep -o) as a representative environment snapshot.
        while IFS= read -r home_dir; do
            local username
            username="$(basename "$home_dir")"
            [[ "$home_dir" == "/root" ]] && username="root"

            # Find the oldest process owned by this user
            local user_pid=""
            user_pid="$(pgrep -u "$username" -o 2>/dev/null || true)"
            [[ -z "$user_pid" ]] && continue

            # /proc/<pid>/environ uses null bytes as delimiters; tr converts
            # them to newlines for line-by-line processing
            local env_file="/proc/${user_pid}/environ"
            [[ -f "$env_file" && -r "$env_file" ]] || continue

            while IFS='=' read -r name value; do
                [[ -z "$name" ]] && continue
                local suspicious="false"
                if in_array "$name" "${SUSPICIOUS_ENV_VARS[@]}"; then
                    suspicious="true"
                fi
                artifacts+=("$(json_object \
                    "$(json_kvs "name" "$name")" \
                    "$(json_kvs "value" "$value")" \
                    "$(json_kvs "scope" "user:${username}")" \
                    "$(json_kvb "suspicious" "$suspicious")"
                )")
            done < <(tr '\0' '\n' < "$env_file" 2>/dev/null | sort)
        done < <(get_user_homes)

    elif is_darwin; then
        # ── launchctl environment (macOS) ──
        # launchctl getenv queries the launchd environment, which is the
        # parent environment for all user-space processes on macOS.
        # Only a fixed set of well-known variables is queried because
        # launchctl getenv requires the exact variable name (no "list all").
        for var in PATH HOME SHELL TMPDIR USER LOGNAME; do
            local val
            val="$(launchctl getenv "$var" 2>/dev/null || true)"
            [[ -z "$val" ]] && continue
            local suspicious="false"
            in_array "$var" "${SUSPICIOUS_ENV_VARS[@]}" && suspicious="true"
            artifacts+=("$(json_object \
                "$(json_kvs "name" "$var")" \
                "$(json_kvs "value" "$val")" \
                "$(json_kvs "scope" "launchctl")" \
                "$(json_kvb "suspicious" "$suspicious")"
            )")
        done
    fi

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "environment" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "environment" "$result"
}
