#!/usr/bin/env bash
# ============================================================================
# Collector: network
# ============================================================================
#
# Purpose:
#   Captures the current network state of the system: active connections,
#   DNS configuration, and the ARP cache. Network data is essential for
#   identifying C2 channels, lateral movement, DNS hijacking, and ARP
#   spoofing during incident response.
#
# Artifacts gathered:
#   - Active network connections (protocol, local/remote addresses, state, process)
#   - DNS configuration (resolvers, search domains)
#   - ARP table entries (hostname, IP, MAC address)
#
# Platform support:
#   Linux:
#     - ss -tunap (preferred) or netstat -tunap (fallback) for connections
#     - /etc/resolv.conf for DNS configuration
#     - arp -a for ARP cache
#   macOS:
#     - lsof -i -nP for connections (ss/netstat -tunap not available on macOS)
#     - scutil --dns for DNS resolver configuration
#     - arp -a for ARP cache (same as Linux)
#
# Performance optimization:
#   All three data sources (connections, DNS, ARP) use awk for bulk JSON
#   generation, avoiding per-line subshell spawns and O(n^2) string
#   concatenation. Connection tables can have hundreds of entries on busy
#   servers, making this critical for performance.
#
# Output:
#   Single combined JSON artifact with "connections", "dns", and "arp" keys,
#   written via write_collector_result.
# ============================================================================

# collect_network — captures network connections, DNS config, and ARP table
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Connection enumeration differs significantly between platforms:
#     - Linux uses ss (modern) or netstat (legacy), both with -tunap flags
#       for TCP/UDP, numeric addresses, and process info
#     - macOS uses lsof -i -nP since ss is unavailable and macOS netstat
#       lacks the -p flag for process association
#   DNS collection:
#     - Linux parses /etc/resolv.conf directives directly
#     - macOS uses scutil --dns which reports the full resolver chain
#       (including per-interface and VPN resolvers) but is limited to 50
#       lines to avoid excessive output
#   ARP collection is identical on both platforms.
collect_network() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local conn_json="[]"
    local dns_json="[]"
    local arp_json="[]"

    # ── Network connections ──
    # Each platform branch uses awk for bulk JSON to avoid per-connection overhead
    if is_linux; then
        # Prefer ss over netstat — ss reads directly from kernel netlink sockets
        # and is faster than netstat which parses /proc/net/*
        if has_cmd ss; then
            conn_json="$(ss -tunap 2>/dev/null | tail -n +2 | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            BEGIN { printf "[" }
            NR > 1 { printf ", " }
            {
                printf "{\"protocol\": \"%s\", \"local_address\": \"%s\", \"remote_address\": \"%s\", \"status\": \"%s\", \"process\": \"%s\"}", \
                    esc($1), esc($5), esc($6), esc($2), esc($7)
            }
            END { printf "]" }
            ')"
        elif has_cmd netstat; then
            # netstat fallback for older systems without ss
            # tail -n +3 skips both the header and the column-names row
            conn_json="$(netstat -tunap 2>/dev/null | tail -n +3 | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            BEGIN { printf "[" }
            NR > 1 { printf ", " }
            {
                printf "{\"protocol\": \"%s\", \"local_address\": \"%s\", \"remote_address\": \"%s\", \"status\": \"%s\"}", \
                    esc($1), esc($4), esc($5), esc($6)
            }
            END { printf "]" }
            ')"
        fi
    elif is_darwin; then
        # macOS lacks ss and netstat -p, so lsof -i is used to associate
        # network connections with process names and PIDs.
        # -nP disables hostname/port name resolution for speed and accuracy.
        if has_cmd lsof; then
            conn_json="$(lsof -i -nP 2>/dev/null | tail -n +2 | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            $5 ~ /IPv[46]/ {
                split($9, addr, "->")
                if (NR > first) printf ", "
                first = 1
                printf "{\"protocol\": \"%s\", \"local_address\": \"%s\", \"remote_address\": \"%s\", \"status\": \"%s\", \"process_name\": \"%s\", \"pid\": %s}", \
                    esc($5), esc(addr[1]), esc(addr[2]), esc($10), esc($1), $2
            }
            BEGIN { printf "["; first = 0 }
            END { printf "]" }
            ')"
        fi
    fi

    # ── DNS configuration ──
    if is_darwin; then
        # scutil --dns reports the full DNS resolver chain including
        # per-interface and VPN-specific resolvers; head -50 caps output
        # to avoid enormous results on systems with many network services
        if has_cmd scutil; then
            local dns_raw
            dns_raw="$(scutil --dns 2>/dev/null | head -50 || true)"
            dns_json="[$(json_object "$(json_kvs "source" "scutil")" "$(json_kvs "raw" "$dns_raw")")]"
        fi
    else
        # Parse /etc/resolv.conf line-by-line, skipping comments and blanks.
        # Each directive (nameserver, search, domain, options) becomes a
        # separate JSON object for structured analysis.
        if [[ -f /etc/resolv.conf ]]; then
            dns_json="$(grep -v '^#' /etc/resolv.conf 2>/dev/null | grep -v '^$' | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            BEGIN { printf "[" }
            NR > 1 { printf ", " }
            {
                dir=$1; $1=""; sub(/^ /, "", $0)
                printf "{\"directive\": \"%s\", \"value\": \"%s\"}", esc(dir), esc($0)
            }
            END { printf "]" }
            ')"
        fi
    fi

    # ── ARP table ──
    # arp -a works identically on macOS and Linux; "incomplete" entries are
    # filtered out since they represent stale/unreachable hosts with no MAC
    if has_cmd arp; then
        arp_json="$(arp -a 2>/dev/null | grep -v incomplete | awk '
        function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/[()]/, "", s); return s }
        BEGIN { printf "[" }
        NR > 1 { printf ", " }
        {
            printf "{\"hostname\": \"%s\", \"ip_address\": \"%s\", \"mac_address\": \"%s\"}", \
                esc($1), esc($2), esc($4)
        }
        END { printf "]" }
        ')"
    fi

    # Combine all three network data sources into a single structured artifact
    local combined
    combined="$(json_object \
        "$(json_kv "connections" "$conn_json")" \
        "$(json_kv "dns" "$dns_json")" \
        "$(json_kv "arp" "$arp_json")"
    )"

    local artifacts_json
    artifacts_json="[${combined}]"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "network" "$artifacts_json" 0 "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "network" "$result"
}
