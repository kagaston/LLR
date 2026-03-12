#!/usr/bin/env bash
# ============================================================================
# Collector: firewall
# ============================================================================
#
# Purpose:
#   Captures firewall rules and configuration from all available firewall
#   subsystems. Firewall data reveals whether host-based filtering is active,
#   what ports are allowed/blocked, and whether an attacker has modified
#   rules to permit C2 traffic or disable protections.
#
# Artifacts gathered:
#   Per rule/entry: the source firewall subsystem, chain (for iptables),
#   rule type, and the rule text or raw configuration output.
#
# Platform support:
#   Linux (checks all three — systems may have multiple active):
#     - iptables: traditional netfilter rules (iptables -L -n -v)
#       Parsed line-by-line; "Chain" lines set the current chain context
#       for subsequent rule lines
#     - nftables: modern netfilter replacement (nft list ruleset)
#       Stored as raw output since nftables ruleset syntax is complex
#       and better analyzed as-is
#     - ufw: Ubuntu's user-friendly iptables frontend (ufw status verbose)
#       Each line of output is stored individually
#   macOS:
#     - pfctl: BSD packet filter rules (pfctl -sr)
#       Each rule line is stored individually
#     - Application Firewall (socketfilterfw): macOS-specific per-app
#       firewall that controls which applications can accept incoming
#       connections. Global state and per-app rules are collected.
#
# Output:
#   JSON array of firewall rule artifacts, written via write_collector_result.
# ============================================================================

# collect_firewall — captures firewall rules from all subsystems
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Linux and macOS have completely different firewall architectures:
#     - Linux uses netfilter (iptables/nftables) with optional ufw frontend
#     - macOS uses pf (BSD packet filter) plus a proprietary Application
#       Firewall for GUI app network access control
#   The collector checks for each subsystem independently since multiple
#   may be active simultaneously (e.g., both iptables and ufw on Ubuntu).
#
# Notes:
#   iptables and pfctl require root/sudo to read rules. If the tool runs
#   without elevated privileges, these commands will fail silently (stderr
#   redirected to /dev/null) and return empty results.
collect_firewall() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()

    if is_linux; then
        # ── iptables ──
        # -L lists all chains, -n shows numeric addresses (avoids DNS lookups),
        # -v adds packet/byte counters. Chain headers are parsed to track
        # which chain subsequent rules belong to.
        if has_cmd iptables; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if [[ "$line" =~ ^Chain ]]; then
                    # Track the current chain name for rule context
                    local chain
                    chain="$(echo "$line" | awk '{print $2}')"
                else
                    # Skip column header lines (start with "pkts" or "num")
                    [[ "$line" =~ ^pkts || "$line" =~ ^num ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "source" "iptables")" \
                        "$(json_kvs "chain" "${chain:-}")" \
                        "$(json_kvs "rule" "$line")"
                    )")
                fi
            done < <(iptables -L -n -v 2>/dev/null)
        fi

        # ── nftables ──
        # nft list ruleset outputs the full configuration in nftables syntax.
        # Stored as raw text because the nested table/chain/rule structure
        # is complex and better suited for human review or specialized parsing.
        if has_cmd nft; then
            local nft_out
            nft_out="$(nft list ruleset 2>/dev/null || true)"
            if [[ -n "$nft_out" ]]; then
                artifacts+=("$(json_object \
                    "$(json_kvs "source" "nftables")" \
                    "$(json_kvs "raw" "$nft_out")"
                )")
            fi
        fi

        # ── ufw ──
        # ufw is Ubuntu's simplified iptables frontend; "status verbose" shows
        # the effective rules plus the default policy and logging settings
        if has_cmd ufw; then
            local ufw_out
            ufw_out="$(ufw status verbose 2>/dev/null || true)"
            if [[ -n "$ufw_out" ]]; then
                while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "source" "ufw")" \
                        "$(json_kvs "rule" "$line")"
                    )")
                done <<< "$ufw_out"
            fi
        fi

    elif is_darwin; then
        # ── pf (packet filter) ──
        # pfctl -sr shows the currently loaded pf rules. pf is the default
        # packet filter on macOS, inherited from BSD.
        if has_cmd pfctl; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                artifacts+=("$(json_object \
                    "$(json_kvs "source" "pfctl")" \
                    "$(json_kvs "rule" "$line")"
                )")
            done < <(pfctl -sr 2>/dev/null)
        fi

        # ── Application Firewall (socketfilterfw) ──
        # macOS's Application Firewall controls per-application incoming
        # connection permissions. It's separate from pf and operates at
        # the application layer.
        local alf_bin="/usr/libexec/ApplicationFirewall/socketfilterfw"
        if [[ -x "$alf_bin" ]]; then
            # Global state reveals whether the firewall is enabled/disabled
            local alf_state
            alf_state="$($alf_bin --getglobalstate 2>/dev/null || true)"
            artifacts+=("$(json_object \
                "$(json_kvs "source" "application_firewall")" \
                "$(json_kvs "type" "global_state")" \
                "$(json_kvs "state" "$alf_state")"
            )")

            # Per-app rules show which applications are allowed/blocked
            local alf_apps
            alf_apps="$($alf_bin --listapps 2>/dev/null || true)"
            if [[ -n "$alf_apps" ]]; then
                while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    artifacts+=("$(json_object \
                        "$(json_kvs "source" "application_firewall")" \
                        "$(json_kvs "type" "app_rule")" \
                        "$(json_kvs "entry" "$line")"
                    )")
                done <<< "$alf_apps"
            fi
        fi
    fi

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "firewall" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "firewall" "$result"
}
