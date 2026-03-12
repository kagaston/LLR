#!/usr/bin/env bash
# ============================================================================
# Collector: system_info
# ============================================================================
#
# Purpose:
#   Collects comprehensive system identification and hardware inventory data
#   for DFIR triage. This is typically the first collector to run, establishing
#   the baseline identity of the target machine (hostname, OS, hardware specs,
#   network interfaces, uptime, and domain membership).
#
# Artifacts gathered:
#   - Hostname and FQDN
#   - OS name, version, and release/build identifiers
#   - CPU model, logical/physical core counts
#   - Total RAM (converted to MB for consistency)
#   - Boot time and calculated uptime in seconds
#   - Architecture (x86_64, arm64, etc.)
#   - Kernel version
#   - Domain membership (AD on macOS, DNS search domain on Linux)
#   - All network interfaces with IPv4/IPv6 addresses
#
# Platform support:
#   macOS:
#     - sw_vers for OS version and build
#     - sysctl for CPU info, RAM (hw.memsize), boot time (kern.boottime)
#     - dsconfigad for Active Directory domain membership
#     - ifconfig for network interface enumeration
#   Linux:
#     - /etc/os-release for distro name, version, and release string
#     - /proc/cpuinfo for CPU model and core counts, nproc as fallback
#     - /proc/meminfo for total RAM
#     - /proc/uptime for boot time calculation
#     - /etc/resolv.conf search directive for domain detection
#     - ip -o addr show for network interface enumeration
#
# Output:
#   Single JSON artifact with all system properties, written via
#   write_collector_result to the output directory.
# ============================================================================

# collect_system_info — gathers system identity, hardware, and network data
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   macOS uses sysctl/sw_vers/ifconfig; Linux uses /proc, /etc/os-release, ip.
#   Boot time extraction differs significantly: macOS kern.boottime returns a
#   struct that must be parsed with awk, while Linux computes it from
#   /proc/uptime relative to current epoch.
#
# Network interface enumeration:
#   Both platforms use awk to parse interface listings into JSON in a single
#   pass, avoiding per-interface subshell overhead. macOS ifconfig output is
#   stateful (interface name on header lines, addresses on indented lines),
#   so awk tracks the current interface name across lines.
collect_system_info() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local hostname_val fqdn_val os_name os_version os_release arch kernel_version
    local cpu_logical cpu_physical cpu_model ram_total_kb ram_total_mb
    local boot_epoch uptime_sec domain_val

    hostname_val="$(hostname 2>/dev/null || echo "unknown")"
    fqdn_val="$(hostname -f 2>/dev/null || echo "$hostname_val")"
    arch="$(uname -m 2>/dev/null || echo "unknown")"
    kernel_version="$(uname -r 2>/dev/null || echo "unknown")"

    if is_darwin; then
        os_name="macOS"
        os_version="$(sw_vers -productVersion 2>/dev/null || echo "unknown")"
        os_release="$(sw_vers -buildVersion 2>/dev/null || echo "unknown")"
        cpu_logical="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 0)"
        cpu_physical="$(sysctl -n hw.physicalcpu 2>/dev/null || echo 0)"
        cpu_model="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")"
        ram_total_kb=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 ))
        # kern.boottime returns a struct like "{ sec = 1234567890, usec = 0 }"
        # — awk extracts the value after "sec" to get the boot epoch
        boot_epoch="$(sysctl -n kern.boottime 2>/dev/null | awk -F'[= ,}]' '{for(i=1;i<=NF;i++) if($i=="sec") print $(i+1)}')"
        # dsconfigad reports Active Directory binding; empty string if unbound
        domain_val="$(dsconfigad -show 2>/dev/null | awk -F'= ' '/Active Directory Domain/{print $2}' || echo "")"
    else
        # Source /etc/os-release in a subshell to extract distro metadata
        # without polluting the current environment
        os_name="$(. /etc/os-release 2>/dev/null && echo "$NAME" || echo "Linux")"
        os_version="$(. /etc/os-release 2>/dev/null && echo "$VERSION_ID" || echo "unknown")"
        os_release="$(. /etc/os-release 2>/dev/null && echo "$VERSION" || uname -r)"
        cpu_logical="$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 0)"
        cpu_physical="$(grep 'cpu cores' /proc/cpuinfo 2>/dev/null | head -1 | awk -F: '{print $2}' | tr -d ' ' || echo 0)"
        cpu_model="$(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | awk -F: '{print $2}' | sed 's/^ //' || echo "unknown")"
        ram_total_kb="$(grep '^MemTotal' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)"
        # Calculate boot epoch by subtracting uptime seconds from current time
        boot_epoch="$(awk '{printf "%d", systime() - $1}' /proc/uptime 2>/dev/null || date +%s)"
        # DNS search domain serves as a rough proxy for domain membership on Linux
        domain_val="$(grep '^search ' /etc/resolv.conf 2>/dev/null | awk '{print $2}' || echo "")"
    fi

    ram_total_mb=$(( ram_total_kb / 1024 ))
    # Guard against non-numeric or empty boot_epoch values
    [[ -n "$boot_epoch" && "$boot_epoch" =~ ^[0-9]+$ ]] || boot_epoch="$(date +%s)"
    uptime_sec=$(( $(epoch_now) - boot_epoch ))
    # Clamp negative uptime (can happen with clock skew or VM snapshots)
    [[ "$uptime_sec" -lt 0 ]] && uptime_sec=0
    local boot_time
    boot_time="$(epoch_to_iso "$boot_epoch")"

    # Network interfaces — build JSON array in a single awk pass per platform
    # to avoid spawning a subshell per interface
    local ifaces_json=""
    if is_darwin; then
        # ifconfig output is stateful: interface name appears on unindented lines,
        # inet/inet6 addresses on indented lines beneath the current interface
        ifaces_json="$(ifconfig 2>/dev/null | awk '
            /^[a-z]/ { iface=$1; sub(/:$/,"",iface) }
            /inet / { ip=$2; printf "{\"interface\": \"%s\", \"family\": \"IPv4\", \"address\": \"%s\"},\n", iface, ip }
            /inet6/ { ip=$2; printf "{\"interface\": \"%s\", \"family\": \"IPv6\", \"address\": \"%s\"},\n", iface, ip }
        ' | sed '$ s/,$//')"
    else
        # ip -o addr show produces one-line-per-address output, making awk
        # parsing straightforward; CIDR prefix is split off to get bare address
        ifaces_json="$(ip -o addr show 2>/dev/null | awk '{
            split($4,a,"/");
            family=($3=="inet")?"IPv4":"IPv6";
            printf "{\"interface\": \"%s\", \"family\": \"%s\", \"address\": \"%s\"},\n", $2, family, a[1]
        }' | sed '$ s/,$//')"
    fi
    [[ -z "$ifaces_json" ]] && ifaces_json=""

    local artifact
    artifact="$(json_object \
        "$(json_kvs "hostname" "$hostname_val")" \
        "$(json_kvs "fqdn" "$fqdn_val")" \
        "$(json_kvs "os_name" "$os_name")" \
        "$(json_kvs "os_version" "$os_version")" \
        "$(json_kvs "os_release" "$os_release")" \
        "$(json_kvs "architecture" "$arch")" \
        "$(json_kvs "kernel_version" "$kernel_version")" \
        "$(json_kvn "cpu_count_logical" "$cpu_logical")" \
        "$(json_kvn "cpu_count_physical" "$cpu_physical")" \
        "$(json_kvs "cpu_model" "$cpu_model")" \
        "$(json_kvn "ram_total_mb" "$ram_total_mb")" \
        "$(json_kvs "boot_time" "$boot_time")" \
        "$(json_kvn "uptime_seconds" "$uptime_sec")" \
        "$(json_kvs "domain" "$domain_val")" \
        "$(json_kv "network_interfaces" "[${ifaces_json}]")"
    )"

    local artifacts_json
    artifacts_json="$(json_array "$artifact")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "system_info" "$artifacts_json" 1 "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "system_info" "$result"
}
