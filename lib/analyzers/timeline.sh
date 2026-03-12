#!/usr/bin/env bash
# =============================================================================
# IntrusionInspector — Timeline Analyzer
# =============================================================================
#
# Purpose:
#   Aggregates timestamps from ALL collector outputs into a single sorted
#   "super timeline" — a chronologically ordered view of every timestamped
#   event across processes, network connections, logins, persistence entries,
#   and more. This is a core DFIR technique that lets investigators correlate
#   events across data sources and identify attack sequences.
#
# Detection Methods:
#   - ISO 8601 timestamp extraction via regex across all raw JSON files
#   - Collection-time metadata extraction ("collected_at" fields)
#   - Login event extraction from users.json raw output lines
#   - Chronological sorting to surface temporal anomalies
#
# Data Sources Examined:
#   - All files matching <output_dir>/raw/*.json (timestamp extraction)
#   - <output_dir>/raw/users.json specifically for login event enrichment
#
# MITRE ATT&CK Mapping:
#   The timeline itself does not map to a specific technique — it is an
#   investigative aid. However, temporal clustering of events often reveals
#   attack chains (e.g., initial access → execution → persistence within a
#   narrow time window), which analysts use to reconstruct the kill chain.
#
# Output:
#   Writes <output_dir>/analysis/timeline.json containing a sorted array
#   of {timestamp, source, event_type, detail} event objects.
# =============================================================================

# Builds a sorted super timeline from all collected artifact timestamps.
# Usage: analyze_timeline <output_dir>
# Args:
#   output_dir - Root output directory containing raw/ and analysis/ subdirs
# Output:
#   Creates analysis/timeline.json with chronologically sorted events
# Design:
#   Events are collected into a bash array, then sorted by timestamp using
#   text-based sort on the JSON timestamp field. This approach avoids
#   date-parsing overhead and works correctly for ISO 8601 strings because
#   they sort lexicographically in chronological order.
analyze_timeline() {
    local output_dir="$1"
    local events=()

    # Phase 1: Extract timestamps from all raw collector JSON files.
    # Each collector writes a JSON file during collection; this loop harvests
    # every ISO 8601 timestamp found in any of them.
    for raw_file in "${output_dir}/raw"/*.json; do
        [[ -f "$raw_file" ]] || continue
        local source
        source="$(basename "$raw_file" .json)"

        # Regex targets ISO 8601 format: YYYY-MM-DDTHH:MM:SS with optional Z suffix.
        # Results are deduped (sort -u) and capped at 1000 to prevent memory
        # exhaustion on large log files with millions of timestamps.
        while IFS= read -r ts; do
            [[ -z "$ts" ]] && continue
            # Strip surrounding quotes and whitespace left over from grep output
            ts="$(echo "$ts" | tr -d '"' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')"
            [[ -z "$ts" ]] && continue

            events+=("$(json_object \
                "$(json_kvs "timestamp" "$ts")" \
                "$(json_kvs "source" "$source")"
            )")
        done < <(grep -oE '"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[Z]?"' "$raw_file" 2>/dev/null | head -1000 | sort -u)

        # Extract the collector's own execution timestamp so investigators can
        # see when each data source was actually captured
        local collected_at
        collected_at="$(grep -o '"collected_at": "[^"]*"' "$raw_file" 2>/dev/null | head -1 | sed 's/.*": "//;s/"//')"
        if [[ -n "$collected_at" ]]; then
            events+=("$(json_object \
                "$(json_kvs "timestamp" "$collected_at")" \
                "$(json_kvs "source" "$source")" \
                "$(json_kvs "event_type" "collection")"
            )")
        fi
    done

    # Phase 2: Enrich the timeline with login events from the users collector.
    # Login entries include the raw "who"/"last" output as detail for analyst review.
    # These are timestamped with the current UTC time because the raw login output
    # format varies across platforms and parsing each variant's timestamp would be
    # fragile. Capped at 50 entries to keep the timeline manageable.
    local users_file="${output_dir}/raw/users.json"
    if [[ -f "$users_file" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            events+=("$(json_object \
                "$(json_kvs "timestamp" "$(utc_now)")" \
                "$(json_kvs "source" "users")" \
                "$(json_kvs "event_type" "login")" \
                "$(json_kvs "detail" "$line")"
            )")
        done < <(grep -o '"raw": "[^"]*"' "$users_file" 2>/dev/null | sed 's/"raw": "//;s/"$//' | head -50)
    fi

    # Phase 3: Sort all events chronologically.
    # Sorts on the 4th double-quote-delimited field, which corresponds to the
    # "timestamp" value in the JSON object. ISO 8601 timestamps sort correctly
    # with lexicographic ordering, so a simple text sort produces chronological
    # order without date parsing.
    local sorted_events
    if [[ ${#events[@]} -gt 0 ]]; then
        sorted_events="$(printf '%s\n' "${events[@]}" | sort -t'"' -k4)"
    else
        sorted_events=""
    fi

    # Phase 4: Manually build the JSON array from sorted lines.
    # This avoids json_array because the events need to maintain their
    # post-sort order, and piping through printf would lose that ordering.
    local events_array="["
    local first=true
    while IFS= read -r evt; do
        [[ -z "$evt" ]] && continue
        if [[ "$first" == "true" ]]; then first=false; else events_array+=", "; fi
        events_array+="$evt"
    done <<< "$sorted_events"
    events_array+="]"

    local result
    result="$(json_object \
        "$(json_kvs "analyzer" "timeline")" \
        "$(json_kvn "event_count" "${#events[@]}")" \
        "$(json_kv "events" "$events_array")"
    )"

    json_write "${output_dir}/analysis/timeline.json" "$result"
    log_info "Timeline: ${#events[@]} events"
}
