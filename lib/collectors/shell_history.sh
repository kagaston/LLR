#!/usr/bin/env bash
# ============================================================================
# Collector: shell_history
# ============================================================================
#
# Purpose:
#   Collects command history from bash, zsh, sh, and fish shells for all
#   users on the system. Shell history is one of the highest-value DFIR
#   artifacts — it reveals exactly what commands an attacker (or compromised
#   account) executed, including reconnaissance, lateral movement, data
#   exfiltration, and cleanup attempts.
#
# Artifacts gathered:
#   Per history entry: the command text, username, shell type (bash/zsh/sh/
#   fish), and line number within the history file.
#
# Platform support:
#   macOS and Linux (identical behavior):
#     - Iterates over all user home directories via get_user_homes
#     - Reads SHELL_HISTORY_FILES (e.g., .bash_history, .zsh_history,
#       .sh_history) from each home directory
#     - Reads FISH_HISTORY_SUBPATH (e.g., .local/share/fish/fish_history)
#       for fish shell users
#     - History file paths are the same on both platforms
#
# Shell-specific parsing:
#   - bash/sh: one command per line, no metadata prefix
#   - zsh: lines may have extended history format ": timestamp:duration;command"
#     which is stripped to extract just the command portion
#   - fish: YAML-like format where commands appear as "- cmd: <command>"
#     entries; only lines matching this pattern are collected
#
# Collection limits:
#   - tail -n 1000 for bash/zsh/sh to capture recent history without
#     reading potentially enormous history files
#   - tail -n 2000 for fish (fish history has metadata lines interspersed,
#     so more raw lines are needed to get a comparable command count)
#
# Output:
#   JSON array of command history artifacts, written via write_collector_result.
# ============================================================================

# collect_shell_history — reads command history from all user shells
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Identical on macOS and Linux. History file locations are the same
#   under user home directories on both platforms.
#
# Username derivation:
#   The username is extracted from the home directory path via basename,
#   with a special case for /root (which would otherwise yield "root"
#   from the path but needs explicit handling when the home dir is /root).
collect_shell_history() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()

    while IFS= read -r home_dir; do
        [[ -d "$home_dir" ]] || continue
        local username
        username="$(basename "$home_dir")"
        [[ "$home_dir" == "/root" ]] && username="root"

        # ── Bash / Zsh / Sh history ──
        for hist_file in "${SHELL_HISTORY_FILES[@]}"; do
            local full_path="${home_dir}/${hist_file}"
            [[ -f "$full_path" && -r "$full_path" ]] || continue

            local shell_name
            case "$hist_file" in
                .bash_history) shell_name="bash" ;;
                .zsh_history)  shell_name="zsh" ;;
                .sh_history)   shell_name="sh" ;;
                *)             shell_name="unknown" ;;
            esac

            local line_num=0
            # tail -n 1000 limits collection to the most recent commands,
            # avoiding slow reads of very large history files (some users
            # accumulate hundreds of thousands of lines)
            while IFS= read -r line; do
                line_num=$((line_num + 1))
                [[ -z "$line" ]] && continue
                # Zsh extended history format prefixes each entry with
                # ": <timestamp>:<duration>;" — strip this metadata to
                # extract just the command text
                local cmd="$line"
                if [[ "$shell_name" == "zsh" && "$cmd" =~ ^:\ [0-9]+:[0-9]+\; ]]; then
                    cmd="${cmd#*;}"
                fi

                artifacts+=("$(json_object \
                    "$(json_kvs "command" "$cmd")" \
                    "$(json_kvs "user" "$username")" \
                    "$(json_kvs "shell" "$shell_name")" \
                    "$(json_kvn "line_number" "$line_num")"
                )")
            done < <(tail -n 1000 "$full_path" 2>/dev/null)
        done

        # ── Fish history ──
        # Fish uses a YAML-like format with entries like:
        #   - cmd: git status
        #     when: 1234567890
        # Only lines matching "- cmd:" are collected; the BASH_REMATCH
        # capture group extracts the command text after the prefix.
        local fish_hist="${home_dir}/${FISH_HISTORY_SUBPATH}"
        if [[ -f "$fish_hist" && -r "$fish_hist" ]]; then
            # tail -n 2000 is higher than bash/zsh because fish history
            # files intersperse metadata lines (when:, paths:) between
            # command entries, so more raw lines are needed
            local line_num=0
            while IFS= read -r line; do
                if [[ "$line" =~ ^-\ cmd:\ (.+) ]]; then
                    line_num=$((line_num + 1))
                    local cmd="${BASH_REMATCH[1]}"
                    artifacts+=("$(json_object \
                        "$(json_kvs "command" "$cmd")" \
                        "$(json_kvs "user" "$username")" \
                        "$(json_kvs "shell" "fish")" \
                        "$(json_kvn "line_number" "$line_num")"
                    )")
                fi
            done < <(tail -n 2000 "$fish_hist" 2>/dev/null)
        fi
    done < <(get_user_homes)

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "shell_history" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "shell_history" "$result"
}
