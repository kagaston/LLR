#!/usr/bin/env bash
# ============================================================================
# Collector: users
# ============================================================================
#
# Purpose:
#   Enumerates user accounts, recent login history, and currently active
#   sessions. User data is critical for identifying unauthorized accounts,
#   suspicious logins (unusual times, remote hosts), and active attacker
#   sessions during incident response.
#
# Artifacts gathered:
#   - User accounts: username, UID, GID, home directory, shell, system flag
#   - Login history: last 20 login events with user, terminal, host, raw line
#   - Active sessions: currently logged-in users with TTY, source, idle time
#
# Platform support:
#   Linux:
#     - /etc/passwd for user account enumeration (uid < 1000 = system account)
#     - last -20 for recent login history from wtmp
#     - w -h for active sessions (headerless output)
#   macOS:
#     - dscl . list /Users for account enumeration, with per-user dscl reads
#       for UID, GID, home, and shell (no /etc/passwd equivalent on macOS)
#     - Underscore-prefixed usernames (_www, _spotlight) and uid < 500 are
#       flagged as system accounts (macOS convention differs from Linux)
#     - last -20 and w -h work identically to Linux
#
# Output:
#   Single combined JSON artifact with "accounts", "logins", and "sessions"
#   arrays, written via write_collector_result.
# ============================================================================

# collect_users — enumerates accounts, login history, and active sessions
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Account enumeration is the primary platform difference:
#     - Linux reads /etc/passwd directly (fast, single file read)
#     - macOS calls dscl per user, which is slower but necessary since macOS
#       uses Open Directory instead of flat passwd files. Each attribute
#       (UniqueID, PrimaryGroupID, NFSHomeDirectory, UserShell) requires a
#       separate dscl read.
#   System account detection thresholds differ:
#     - Linux: uid < 1000 (except root at 0)
#     - macOS: underscore prefix OR uid < 500 (except root at 0)
#   Login history and session commands are identical on both platforms.
collect_users() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local account_artifacts=()
    local login_artifacts=()
    local session_artifacts=()

    # ── User accounts ──
    if is_linux; then
        # Parse /etc/passwd colon-delimited fields directly; faster than
        # calling getent or id per user
        if [[ -f /etc/passwd ]]; then
            while IFS=: read -r uname x uid gid gecos home shell; do
                local is_system="false"
                # UIDs below 1000 are system/service accounts by Linux convention
                # (uid 0 = root, handled separately)
                [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && is_system="true"
                account_artifacts+=("$(json_object \
                    "$(json_kvs "username" "$uname")" \
                    "$(json_kvn "uid" "$uid")" \
                    "$(json_kvn "gid" "$gid")" \
                    "$(json_kvs "home" "$home")" \
                    "$(json_kvs "shell" "$shell")" \
                    "$(json_kvb "is_system" "$is_system")"
                )")
            done < /etc/passwd
        fi
    elif is_darwin; then
        # macOS uses Open Directory (dscl) instead of /etc/passwd.
        # Each user requires individual attribute reads, making this
        # inherently slower than the Linux /etc/passwd approach.
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            local uid gid home shell is_system="false"
            uid="$(dscl . -read "/Users/${user}" UniqueID 2>/dev/null | awk '{print $2}')"
            gid="$(dscl . -read "/Users/${user}" PrimaryGroupID 2>/dev/null | awk '{print $2}')"
            home="$(dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
            shell="$(dscl . -read "/Users/${user}" UserShell 2>/dev/null | awk '{print $2}')"
            # macOS system accounts are prefixed with underscore (_www, _spotlight, etc.)
            [[ "$user" == _* ]] && is_system="true"
            # macOS system UIDs are typically below 500 (differs from Linux's 1000)
            [[ -n "$uid" && "$uid" -lt 500 && "$uid" -ne 0 ]] 2>/dev/null && is_system="true"
            account_artifacts+=("$(json_object \
                "$(json_kvs "username" "$user")" \
                "$(json_kvn "uid" "${uid:-0}")" \
                "$(json_kvn "gid" "${gid:-0}")" \
                "$(json_kvs "home" "${home:-}")" \
                "$(json_kvs "shell" "${shell:-}")" \
                "$(json_kvb "is_system" "$is_system")"
            )")
        done < <(dscl . list /Users 2>/dev/null)
    fi

    # ── Login history ──
    # last -20 works identically on macOS and Linux, reading from
    # wtmp (Linux) or the equivalent system log (macOS)
    if has_cmd last; then
        while IFS= read -r line; do
            # Skip empty lines, wtmp rotation markers, and system boot entries
            [[ -z "$line" || "$line" == *"wtmp"* || "$line" == *"boot"* ]] && continue
            local user term host raw
            user="$(echo "$line" | awk '{print $1}')"
            term="$(echo "$line" | awk '{print $2}')"
            host="$(echo "$line" | awk '{print $3}')"
            raw="$line"
            login_artifacts+=("$(json_object \
                "$(json_kvs "username" "$user")" \
                "$(json_kvs "terminal" "$term")" \
                "$(json_kvs "host" "$host")" \
                "$(json_kvs "raw" "$raw")"
            )")
        done < <(last -20 2>/dev/null)
    fi

    # ── Active sessions ──
    # w -h suppresses the header line; output format is consistent across platforms
    if has_cmd w; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local user tty from idle
            user="$(echo "$line" | awk '{print $1}')"
            tty="$(echo "$line" | awk '{print $2}')"
            from="$(echo "$line" | awk '{print $3}')"
            idle="$(echo "$line" | awk '{print $4}')"
            session_artifacts+=("$(json_object \
                "$(json_kvs "username" "$user")" \
                "$(json_kvs "tty" "$tty")" \
                "$(json_kvs "from" "$from")" \
                "$(json_kvs "idle" "$idle")"
            )")
        done < <(w -h 2>/dev/null)
    fi

    local count=$(( ${#account_artifacts[@]} + ${#login_artifacts[@]} + ${#session_artifacts[@]} ))

    # Combine all three user data categories into a single structured artifact.
    # The ${arr[@]+"${arr[@]}"} pattern safely handles empty arrays in bash
    # strict mode (set -u) by only expanding if the array has elements.
    local combined
    combined="$(json_object \
        "$(json_kv "accounts" "$(json_array "${account_artifacts[@]+"${account_artifacts[@]}"}")")" \
        "$(json_kv "logins" "$(json_array "${login_artifacts[@]+"${login_artifacts[@]}"}")")" \
        "$(json_kv "sessions" "$(json_array "${session_artifacts[@]+"${session_artifacts[@]}"}")")"
    )"

    local artifacts_json
    artifacts_json="$(json_array "$combined")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "users" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "users" "$result"
}
