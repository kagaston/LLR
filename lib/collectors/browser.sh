#!/usr/bin/env bash
# ============================================================================
# Collector: browser
# ============================================================================
#
# Purpose:
#   Extracts browsing history from Chrome, Firefox, and Safari databases.
#   Browser history is valuable for DFIR because it reveals phishing URLs
#   visited, malware download sources, C2 panel access, and attacker
#   reconnaissance activity on compromised hosts.
#
# Artifacts gathered:
#   Per history entry: browser name, URL, page title, visit count,
#   last visit timestamp, and the database file path (for provenance).
#
# Platform support:
#   Linux:
#     - Chrome: ~/.config/google-chrome/Default/History (SQLite)
#     - Firefox: ~/.mozilla/firefox/*.default*/places.sqlite (glob)
#     - Safari: not available on Linux
#   macOS:
#     - Chrome: ~/Library/Application Support/Google/Chrome/Default/History
#     - Firefox: ~/Library/Application Support/Firefox/Profiles/*.default*/places.sqlite
#     - Safari: ~/Library/Safari/History.db (macOS only)
#
# Dependencies:
#   Requires sqlite3 to be installed. If sqlite3 is not found, the collector
#   logs a warning and returns an empty artifact set (does not fail).
#
# Database locking strategy:
#   All browser databases are copied to a temp file before querying.
#   This is critical because browsers hold WAL locks on their live SQLite
#   databases — querying them directly could either fail with SQLITE_BUSY
#   or cause data corruption. The temp copy ensures a consistent snapshot
#   without interfering with the running browser.
#
# Timestamp handling:
#   Each browser stores timestamps differently:
#     - Chrome: microseconds since 1601-01-01 (WebKit epoch)
#       → converted via (last_visit_time/1000000 - 11644473600)
#     - Firefox: microseconds since Unix epoch
#       → converted via (last_visit_date/1000000)
#     - Safari: seconds since 2001-01-01 (Core Data epoch)
#       → converted via (visit_time + 978307200)
#
# Output:
#   JSON array of browser history artifacts (capped at 500 per browser per
#   user), written via write_collector_result.
# ============================================================================

# collect_browser — extracts browsing history from Chrome, Firefox, Safari
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Database paths differ by platform (Linux vs macOS profile directories).
#   Safari collection is macOS-only. Chrome and Firefox use the same SQLite
#   schema on both platforms — only the file paths differ.
#
# Performance:
#   Results are limited to 500 rows per database (ORDER BY last_visit DESC)
#   to bound collection time while capturing the most forensically relevant
#   recent history.
collect_browser() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()

    # sqlite3 is required for all browser history extraction
    if ! has_cmd sqlite3; then
        log_warn "sqlite3 not found — skipping browser history collection"
        local end_ts
        end_ts="$(epoch_now)"
        local result
        result="$(collector_output "browser" "[]" 0 "$start_ts" "$end_ts")"
        write_collector_result "$output_dir" "browser" "$result"
        return 0
    fi

    # Single temp file reused for all database copies; cleaned up on return
    local tmp_db
    tmp_db="$(mktemp)"
    trap "rm -f '$tmp_db'" RETURN

    while IFS= read -r home_dir; do
        # ── Chrome ──
        local chrome_db=""
        if is_linux; then
            chrome_db="${home_dir}/${CHROME_HISTORY_LINUX}"
        elif is_darwin; then
            chrome_db="${home_dir}/${CHROME_HISTORY_MACOS}"
        fi

        if [[ -n "$chrome_db" && -f "$chrome_db" ]]; then
            # Copy to temp file to avoid SQLite WAL locking on the live database
            cp "$chrome_db" "$tmp_db" 2>/dev/null
            # Chrome timestamps are microseconds since 1601-01-01 (WebKit epoch);
            # subtract 11644473600 seconds to convert to Unix epoch
            while IFS='|' read -r url title visit_count last_visit; do
                [[ -z "$url" ]] && continue
                artifacts+=("$(json_object \
                    "$(json_kvs "browser" "chrome")" \
                    "$(json_kvs "url" "$url")" \
                    "$(json_kvs "title" "$title")" \
                    "$(json_kvn "visit_count" "${visit_count:-0}")" \
                    "$(json_kvs "last_visit" "${last_visit:-}")" \
                    "$(json_kvs "db_path" "$chrome_db")"
                )")
            done < <(sqlite3 "$tmp_db" "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 500;" 2>/dev/null || true)
        fi

        # ── Firefox ──
        local ff_glob=""
        if is_linux; then
            ff_glob="${home_dir}/${FIREFOX_GLOB_LINUX}"
        elif is_darwin; then
            ff_glob="${home_dir}/${FIREFOX_GLOB_MACOS}"
        fi

        if [[ -n "$ff_glob" ]]; then
            # Firefox uses profile directories with random prefixes (e.g.,
            # abc123.default-release); glob expansion finds all matching profiles
            for ff_db in $ff_glob; do
                [[ -f "$ff_db" ]] || continue
                # Copy to temp to avoid locking the live places.sqlite
                cp "$ff_db" "$tmp_db" 2>/dev/null
                # Firefox timestamps are microseconds since Unix epoch
                while IFS='|' read -r url title visit_count last_visit; do
                    [[ -z "$url" ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "browser" "firefox")" \
                        "$(json_kvs "url" "$url")" \
                        "$(json_kvs "title" "$title")" \
                        "$(json_kvn "visit_count" "${visit_count:-0}")" \
                        "$(json_kvs "last_visit" "${last_visit:-}")" \
                        "$(json_kvs "db_path" "$ff_db")"
                    )")
                done < <(sqlite3 "$tmp_db" "SELECT url, title, visit_count, datetime(last_visit_date/1000000, 'unixepoch') FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 500;" 2>/dev/null || true)
            done
        fi

        # ── Safari (macOS only) ──
        # Safari uses a join between history_items and history_visits tables.
        # Timestamps are seconds since 2001-01-01 (Core Data / NSDate epoch);
        # add 978307200 to convert to Unix epoch.
        if is_darwin; then
            local safari_db="${home_dir}/${SAFARI_HISTORY_MACOS}"
            if [[ -f "$safari_db" ]]; then
                cp "$safari_db" "$tmp_db" 2>/dev/null
                while IFS='|' read -r url title visit_count last_visit; do
                    [[ -z "$url" ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "browser" "safari")" \
                        "$(json_kvs "url" "$url")" \
                        "$(json_kvs "title" "$title")" \
                        "$(json_kvn "visit_count" "${visit_count:-0}")" \
                        "$(json_kvs "last_visit" "${last_visit:-}")" \
                        "$(json_kvs "db_path" "$safari_db")"
                    )")
                done < <(sqlite3 "$tmp_db" "SELECT hi.url, hv.title, hi.visit_count, datetime(hv.visit_time + 978307200, 'unixepoch') FROM history_items hi JOIN history_visits hv ON hi.id = hv.history_item ORDER BY hv.visit_time DESC LIMIT 500;" 2>/dev/null || true)
            fi
        fi
    done < <(get_user_homes)

    rm -f "$tmp_db"

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "browser" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "browser" "$result"
}
