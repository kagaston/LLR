#!/usr/bin/env bash
# ============================================================================
# Collector: persistence
# ============================================================================
#
# Purpose:
#   Enumerates persistence mechanisms that allow programs to survive reboots
#   or user logouts. Persistence is one of the most important DFIR artifacts —
#   attackers almost always install persistence to maintain access. This
#   collector gathers cron jobs, systemd services, init.d scripts, launchd
#   plists, and login items.
#
# Artifacts gathered:
#   - Cron jobs: system crontab, cron directories, per-user crontabs
#   - Systemd services: unit files with ExecStart directives
#   - Init.d scripts: legacy SysV init executable scripts
#   - LaunchDaemons/LaunchAgents: system and user-level plist files
#   - Login items: macOS GUI login items via AppleScript
#
# Platform support:
#   Linux:
#     - /etc/crontab for system-wide cron entries
#     - CRON_DIRS_LINUX (e.g., /etc/cron.d, /etc/cron.daily) for cron dirs
#     - /var/spool/cron/crontabs for per-user crontabs
#     - SYSTEMD_DIRS (e.g., /etc/systemd/system, /usr/lib/systemd/system)
#     - /etc/init.d for SysV init scripts
#   macOS:
#     - LAUNCHD_DIRS_MACOS (e.g., /Library/LaunchDaemons, /Library/LaunchAgents,
#       /System/Library/LaunchDaemons) for system-level launchd plists
#     - ~/Library/LaunchAgents for per-user launchd agents
#     - crontab -l for the current user's cron entries
#     - osascript to query System Events for GUI login items
#
# Output:
#   JSON array of persistence artifacts, each tagged with a "type" field
#   (cron_system, cron_dir, cron_user, systemd_service, initd, launchd,
#   launchd_user, cron, login_item), written via write_collector_result.
# ============================================================================

# collect_persistence — enumerates all persistence mechanisms
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Linux and macOS have entirely different persistence ecosystems:
#     - Linux uses cron + systemd + init.d (three independent subsystems)
#     - macOS uses launchd (primary) + cron (secondary) + login items (GUI)
#   The collector exhaustively enumerates all mechanisms on each platform
#   since attackers may use any of them.
#
# Notes on launchd parsing:
#   The defaults command reads binary plist files natively. The Label
#   property uniquely identifies each launch job. Program or ProgramArguments
#   reveals what binary is executed. If neither is readable, the plist
#   filename is used as a fallback label.
collect_persistence() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()

    if is_linux; then
        # ── System crontab ──
        # /etc/crontab contains system-wide scheduled tasks; comment and
        # blank lines are skipped to capture only active entries
        if [[ -f /etc/crontab ]]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^# ]] && continue
                [[ -z "$line" ]] && continue
                artifacts+=("$(json_object \
                    "$(json_kvs "type" "cron_system")" \
                    "$(json_kvs "source" "/etc/crontab")" \
                    "$(json_kvs "entry" "$line")"
                )")
            done < /etc/crontab
        fi

        # ── Cron directories ──
        # Directories like /etc/cron.d, /etc/cron.daily, /etc/cron.hourly
        # contain drop-in cron scripts; each file is parsed for active entries
        for cron_dir in "${CRON_DIRS_LINUX[@]}"; do
            [[ -d "$cron_dir" ]] || continue
            for cron_file in "$cron_dir"/*; do
                [[ -f "$cron_file" ]] || continue
                while IFS= read -r line; do
                    [[ "$line" =~ ^# ]] && continue
                    [[ -z "$line" ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "type" "cron_dir")" \
                        "$(json_kvs "source" "$cron_file")" \
                        "$(json_kvs "entry" "$line")"
                    )")
                done < "$cron_file"
            done
        done

        # ── Per-user crontabs ──
        # /var/spool/cron/crontabs/<username> contains each user's personal
        # crontab; the username is derived from the filename
        if [[ -d /var/spool/cron/crontabs ]]; then
            for cron_file in /var/spool/cron/crontabs/*; do
                [[ -f "$cron_file" ]] || continue
                local cron_user
                cron_user="$(basename "$cron_file")"
                while IFS= read -r line; do
                    [[ "$line" =~ ^# ]] && continue
                    [[ -z "$line" ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "type" "cron_user")" \
                        "$(json_kvs "user" "$cron_user")" \
                        "$(json_kvs "entry" "$line")"
                    )")
                done < "$cron_file"
            done
        fi

        # ── Systemd services ──
        # Enumerate .service unit files from standard systemd directories.
        # ExecStart reveals the binary that runs when the service starts —
        # a key indicator for malicious services.
        for svc_dir in "${SYSTEMD_DIRS[@]}"; do
            [[ -d "$svc_dir" ]] || continue
            for svc_file in "$svc_dir"/*.service; do
                [[ -f "$svc_file" ]] || continue
                local svc_name exec_start
                svc_name="$(basename "$svc_file")"
                exec_start="$(grep '^ExecStart=' "$svc_file" 2>/dev/null | head -1 | sed 's/^ExecStart=//')"
                artifacts+=("$(json_object \
                    "$(json_kvs "type" "systemd_service")" \
                    "$(json_kvs "name" "$svc_name")" \
                    "$(json_kvs "path" "$svc_file")" \
                    "$(json_kvs "exec_start" "$exec_start")"
                )")
            done
        done

        # ── Init.d scripts ──
        # Legacy SysV init scripts; only executable files are collected
        # since non-executable ones are disabled/inactive
        if [[ -d /etc/init.d ]]; then
            for init_file in /etc/init.d/*; do
                [[ -f "$init_file" && -x "$init_file" ]] || continue
                artifacts+=("$(json_object \
                    "$(json_kvs "type" "initd")" \
                    "$(json_kvs "name" "$(basename "$init_file")")" \
                    "$(json_kvs "path" "$init_file")"
                )")
            done
        fi

    elif is_darwin; then
        # ── LaunchDaemons and LaunchAgents (system-level) ──
        # System-level launchd directories contain plist files that define
        # daemons (run as root, no GUI) and agents (run per-user session).
        # "defaults read" natively handles both XML and binary plist formats.
        for ld_dir in "${LAUNCHD_DIRS_MACOS[@]}"; do
            [[ -d "$ld_dir" ]] || continue
            for plist in "$ld_dir"/*.plist; do
                [[ -f "$plist" ]] || continue
                local label=""
                # Label is the unique identifier for the launch job
                label="$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)"
                local program=""
                # Program is the direct executable path; ProgramArguments is
                # the array form (first element is the binary)
                program="$(defaults read "$plist" Program 2>/dev/null || echo "")"
                if [[ -z "$program" ]]; then
                    program="$(defaults read "$plist" ProgramArguments 2>/dev/null | head -3 | tr -d '\n' || echo "")"
                fi
                artifacts+=("$(json_object \
                    "$(json_kvs "type" "launchd")" \
                    "$(json_kvs "name" "$label")" \
                    "$(json_kvs "path" "$plist")" \
                    "$(json_kvs "program" "$program")"
                )")
            done
        done

        # ── User LaunchAgents ──
        # Per-user ~/Library/LaunchAgents may contain attacker-installed
        # agents that persist across user logouts
        while IFS= read -r home_dir; do
            local la_dir="${home_dir}/Library/LaunchAgents"
            [[ -d "$la_dir" ]] || continue
            for plist in "$la_dir"/*.plist; do
                [[ -f "$plist" ]] || continue
                local label=""
                label="$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)"
                artifacts+=("$(json_object \
                    "$(json_kvs "type" "launchd_user")" \
                    "$(json_kvs "name" "$label")" \
                    "$(json_kvs "path" "$plist")"
                )")
            done
        done < <(get_user_homes)

        # ── Crontab (macOS) ──
        # macOS supports cron alongside launchd; attackers sometimes use it
        # because it's less monitored than launchd
        local cron_out
        cron_out="$(crontab -l 2>/dev/null || true)"
        if [[ -n "$cron_out" ]]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^# ]] && continue
                [[ -z "$line" ]] && continue
                artifacts+=("$(json_object \
                    "$(json_kvs "type" "cron")" \
                    "$(json_kvs "user" "root")" \
                    "$(json_kvs "entry" "$line")"
                )")
            done <<< "$cron_out"
        fi

        # ── Login items ──
        # GUI login items run when a user logs in graphically; queried via
        # AppleScript since there is no CLI equivalent for this data
        if has_cmd osascript; then
            local login_items
            login_items="$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || true)"
            if [[ -n "$login_items" ]]; then
                IFS=', ' read -ra items <<< "$login_items"
                for item in "${items[@]}"; do
                    item="$(echo "$item" | sed 's/^ *//;s/ *$//')"
                    [[ -z "$item" ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "type" "login_item")" \
                        "$(json_kvs "name" "$item")"
                    )")
                done
            fi
        fi
    fi

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "persistence" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "persistence" "$result"
}
