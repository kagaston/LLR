#!/usr/bin/env bash
# ============================================================================
# Collector: clipboard
# ============================================================================
#
# Purpose:
#   Captures the current system clipboard contents and performs basic
#   Indicator of Compromise (IOC) detection on the captured text.
#   Clipboard data can reveal credentials, URLs, IP addresses, or encoded
#   payloads that were recently copied — potentially by an attacker during
#   an active session or by a clipboard-hijacking malware.
#
# Artifacts gathered:
#   - Raw clipboard text content (truncated to 4096 chars if larger)
#   - Content length and truncation flag
#   - IOC detection flags: has_urls, has_ips, has_base64
#   - Extracted IOC values: up to 10 URLs and 10 IP addresses found
#
# Platform support:
#   macOS:
#     - pbpaste: native clipboard access (always available)
#   Linux (tries multiple clipboard tools, in priority order):
#     - xclip -selection clipboard -o: X11 clipboard (most common)
#     - xsel --clipboard --output: X11 clipboard (alternative)
#     - wl-paste: Wayland clipboard (for Wayland-based desktops)
#   Note: on headless Linux servers without a display server, all clipboard
#   tools will fail silently and the collector returns empty results.
#
# IOC detection:
#   The collector scans clipboard content for three categories of IOCs:
#     - URLs: matches http:// and https:// patterns
#     - IPv4 addresses: matches dotted-quad patterns (x.x.x.x)
#     - Base64 blobs: matches 40+ character base64 strings (potential
#       encoded payloads or credentials)
#   Detected IOCs are extracted and included in the artifact for analyst
#   review. URL and IP extraction is capped at 10 matches to prevent
#   excessive output.
#
# Output:
#   JSON array with 0 or 1 clipboard artifact, written via
#   write_collector_result.
# ============================================================================

# collect_clipboard — captures clipboard contents and detects IOCs
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   macOS always has pbpaste available. Linux requires one of xclip, xsel,
#   or wl-paste to be installed. The tools are tried in order; the first
#   successful one is used. If none are available (e.g., headless server),
#   the clipboard content will be empty and no artifact is generated.
#
# Security note:
#   Clipboard content may contain sensitive data (passwords, tokens). The
#   4096-character truncation limit bounds the captured data, but analysts
#   should be aware that clipboard artifacts may contain credentials.
collect_clipboard() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()
    local content=""
    local max_len=4096

    # Platform-specific clipboard access
    if is_darwin; then
        content="$(pbpaste 2>/dev/null || true)"
    elif is_linux; then
        # Try clipboard tools in priority order: xclip (most common on X11),
        # xsel (alternative X11 tool), wl-paste (Wayland)
        if has_cmd xclip; then
            content="$(xclip -selection clipboard -o 2>/dev/null || true)"
        elif has_cmd xsel; then
            content="$(xsel --clipboard --output 2>/dev/null || true)"
        elif has_cmd wl-paste; then
            content="$(wl-paste 2>/dev/null || true)"
        fi
    fi

    if [[ -n "$content" ]]; then
        local content_len=${#content}
        local truncated="false"
        # Truncate to max_len to prevent excessively large artifacts
        # and bound the IOC scanning cost
        if [[ "$content_len" -gt "$max_len" ]]; then
            content="${content:0:$max_len}"
            truncated="true"
        fi

        # ── IOC detection in clipboard ──
        # Simple pattern matching to flag potentially interesting content;
        # not meant to be a comprehensive IOC scanner, just a quick triage signal
        local has_urls="false"
        local has_ips="false"
        local has_base64="false"
        local iocs_found=()

        # URL detection — matches http:// and https:// URLs
        if echo "$content" | grep -qE 'https?://[^ ]+'; then
            has_urls="true"
            while IFS= read -r url; do
                iocs_found+=("$(json_object "$(json_kvs "type" "url")" "$(json_kvs "value" "$url")")")
            done < <(echo "$content" | grep -oE 'https?://[^ ]+' | head -10)
        fi

        # IPv4 detection — matches dotted-quad notation
        if echo "$content" | grep -qE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; then
            has_ips="true"
            while IFS= read -r ip; do
                iocs_found+=("$(json_object "$(json_kvs "type" "ip")" "$(json_kvs "value" "$ip")")")
            done < <(echo "$content" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -10)
        fi

        # Base64 detection — matches long base64 strings (40+ chars)
        # that could be encoded payloads, credentials, or obfuscated commands
        if echo "$content" | grep -qE '[A-Za-z0-9+/]{40,}={0,2}'; then
            has_base64="true"
        fi

        artifacts+=("$(json_object \
            "$(json_kvs "content" "$content")" \
            "$(json_kvn "content_length" "$content_len")" \
            "$(json_kvb "truncated" "$truncated")" \
            "$(json_kvb "has_urls" "$has_urls")" \
            "$(json_kvb "has_ips" "$has_ips")" \
            "$(json_kvb "has_base64" "$has_base64")" \
            "$(json_kv "iocs" "$(json_array "${iocs_found[@]+"${iocs_found[@]}"}")")"
        )")
    fi

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "clipboard" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "clipboard" "$result"
}
