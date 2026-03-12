#!/usr/bin/env bash
# ============================================================================
# Collector: logs
# ============================================================================
#
# Purpose:
#   Collects recent entries from system logs, authentication logs, and
#   journal output. Log data is essential for timeline reconstruction,
#   identifying authentication anomalies, service crashes, and evidence
#   of attacker activity.
#
# Artifacts gathered:
#   Per log source: the source identifier (file path or command name) and
#   the raw log content (last N lines), along with the collection window
#   in days.
#
# Platform support:
#   Linux:
#     - LOG_FILES_LINUX: standard log files (e.g., /var/log/syslog,
#       /var/log/auth.log, /var/log/messages, /var/log/secure)
#     - journalctl: systemd journal entries from the last LOG_COLLECTION_DAYS
#   macOS:
#     - LOG_FILES_MACOS: standard log files (e.g., /var/log/system.log,
#       /var/log/install.log)
#     - log show --last 1m: macOS unified logging (limited to 1 minute with
#       a timeout guard to prevent hangs on busy systems)
#
# Performance optimization:
#   This collector writes JSON directly to a file instead of building it
#   in memory. Log content can be very large (hundreds of KB), and passing
#   it through json_escape + bash string concatenation would cause severe
#   O(n^2) performance degradation. Instead:
#     - awk handles JSON string escaping inline while streaming to the file
#     - Content is streamed through a temp file to avoid holding large
#       strings in bash variables
#     - The final JSON envelope is assembled with printf directly to disk
#
# Output:
#   Writes directly to raw/logs.json in the output directory, bypassing
#   the normal write_collector_result path. Uses jq for pretty-printing
#   if available.
# ============================================================================

# collect_logs — collects recent system and auth log entries
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Log file paths differ between platforms (LOG_FILES_LINUX vs LOG_FILES_MACOS).
#   Linux additionally collects journalctl output (systemd journal).
#   macOS additionally collects from the unified log (log show), which is
#   guarded by a 15-second timeout to prevent hangs — the unified log can
#   be extremely slow on some systems.
#
# File I/O strategy:
#   The collector builds JSON incrementally in a temp file ($tmp_file) to
#   avoid memory pressure from large log content. The final JSON structure
#   is assembled by writing the envelope (header + trailer) directly and
#   cat-ing the temp file for the artifacts array body.
collect_logs() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local max_lines=500
    local raw_dir="${output_dir}/raw"
    ensure_dir "$raw_dir"

    # Write JSON artifacts to a temp file incrementally, then assemble
    # the final output — avoids holding all log content in bash variables
    local out_file="${raw_dir}/logs.json"
    local tmp_file
    tmp_file="$(mktemp)"

    local artifact_count=0

    # _write_log_artifact — streams a single log source's content into the
    # JSON artifacts temp file with proper escaping
    #
    # Parameters:
    #   $1 (source)       — identifier for the log source (file path or command)
    #   $2 (content_file) — path to temp file containing the raw log lines
    #
    # Uses awk for JSON string escaping (backslashes, quotes, tabs, newlines)
    # to avoid the performance cost of bash-level json_escape on large content.
    _write_log_artifact() {
        local source="$1"
        local content_file="$2"

        [[ -s "$content_file" ]] || return 0

        if [[ "$artifact_count" -gt 0 ]]; then
            printf ', ' >> "$tmp_file"
        fi

        # Write the JSON object start with the source field, then stream
        # the escaped content directly from the content file via awk.
        # awk escapes backslashes, double quotes, and tabs, and joins
        # lines with literal \n — this avoids loading the entire content
        # into a bash variable.
        printf '{"log_source": "%s", "content": "' "$source" >> "$tmp_file"
        awk '{
            gsub(/\\/, "\\\\")
            gsub(/"/, "\\\"")
            gsub(/\t/, "\\t")
            if (NR > 1) printf "\\n"
            printf "%s", $0
        }' "$content_file" >> "$tmp_file"
        printf '", "days": %d}' "$LOG_COLLECTION_DAYS" >> "$tmp_file"

        artifact_count=$((artifact_count + 1))
    }

    # Reusable temp file for log content; overwritten per source
    local content_tmp
    content_tmp="$(mktemp)"

    if is_linux; then
        # Collect tail of each standard log file
        for log_file in "${LOG_FILES_LINUX[@]}"; do
            [[ -f "$log_file" && -r "$log_file" ]] || continue
            tail -n "$max_lines" "$log_file" > "$content_tmp" 2>/dev/null || true
            _write_log_artifact "$log_file" "$content_tmp"
        done

        # journalctl provides structured journal entries; --since limits
        # the time window and --no-pager prevents interactive mode
        if has_cmd journalctl; then
            journalctl --since="${LOG_COLLECTION_DAYS} days ago" --no-pager -q 2>/dev/null \
                | tail -n "$max_lines" > "$content_tmp" 2>/dev/null || true
            _write_log_artifact "journalctl" "$content_tmp"
        fi

    elif is_darwin; then
        for log_file in "${LOG_FILES_MACOS[@]}"; do
            [[ -f "$log_file" && -r "$log_file" ]] || continue
            tail -n "$max_lines" "$log_file" > "$content_tmp" 2>/dev/null || true
            _write_log_artifact "$log_file" "$content_tmp"
        done

        # macOS unified log (log show) can be extremely slow on busy systems,
        # so it's wrapped with a 15-second timeout (timeout or gtimeout) and
        # limited to the last 1 minute of log data + head line cap
        if has_cmd log; then
            local timeout_cmd=""
            has_cmd timeout && timeout_cmd="timeout 15"
            has_cmd gtimeout && [[ -z "$timeout_cmd" ]] && timeout_cmd="gtimeout 15"

            $timeout_cmd log show --last 1m --style compact 2>/dev/null \
                | head -n "$max_lines" > "$content_tmp" 2>/dev/null || true
            _write_log_artifact "unified_log" "$content_tmp"
        fi
    fi

    rm -f "$content_tmp"

    local end_ts
    end_ts="$(epoch_now)"
    local duration=$(( end_ts - start_ts ))

    # Assemble the final collector JSON envelope by writing header, then
    # cat-ing the temp artifacts file, then writing the closing bracket.
    # This avoids loading all artifact JSON into a bash variable.
    printf '{"collector_name": "logs", "platform": "%s", "hostname": "%s", "collected_at": "%s", "duration_seconds": %d, "artifact_count": %d, "artifacts": [' \
        "$PLATFORM_LOWER" "$(hostname)" "$(utc_now)" "$duration" "$artifact_count" > "$out_file"
    cat "$tmp_file" >> "$out_file"
    printf ']}\n' >> "$out_file"

    rm -f "$tmp_file"

    # Pretty-print with jq if available for human-readable output
    if has_cmd jq; then
        local pretty
        pretty="$(jq '.' "$out_file" 2>/dev/null)" && printf '%s\n' "$pretty" > "$out_file"
    fi

    audit_log "collector_complete" "Collector logs finished"
}
