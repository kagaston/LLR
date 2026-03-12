#!/usr/bin/env bash
# =============================================================================
# IntrusionInspector — Anomaly Detector Analyzer
# =============================================================================
#
# Purpose:
#   Performs 12 heuristic-based anomaly checks against collected forensic
#   artifacts. Unlike the signature-based IOC scanner, this analyzer looks
#   for behavioral patterns and environmental misconfigurations that are
#   common across many attack campaigns without requiring specific IOC values.
#
# Detection Methods:
#   1.  LOLBins — Living-off-the-Land binaries abused for execution
#   2.  Parent-child process anomalies — shells spawned by unusual parents
#   3.  Temp directory execution — binaries running from /tmp, /var/tmp, /dev/shm
#   4.  Suspicious scheduled tasks — persistence entries with download/exec commands
#   5.  Suspicious network ports — connections on known C2/exfil ports
#   6.  Base64-encoded commands — obfuscation in process args or shell history
#   7.  Unusual services — daemons referencing temp directories
#   8.  PATH hijacking — writable or suspicious directories in $PATH
#   9.  Rogue certificates — self-signed certificates in the trust store
#   10. Suspicious kernel modules — module names suggesting rootkits or keyloggers
#   11. Clipboard IOCs — URLs or IP addresses in clipboard content
#   12. Firewall tampering — host firewall in disabled/inactive state
#
# Data Sources Examined:
#   - raw/processes.json      (checks 1, 2, 3, 6)
#   - raw/network.json        (check 5)
#   - raw/persistence.json    (checks 4, 7)
#   - raw/environment.json    (check 8)
#   - raw/certificates.json   (check 9)
#   - raw/kernel_modules.json (check 10)
#   - raw/clipboard.json      (check 11)
#   - raw/firewall.json       (check 12)
#   - raw/shell_history.json  (check 6)
#
# MITRE ATT&CK Mapping:
#   Each heuristic check maps to a specific ATT&CK technique:
#     T1218 (Signed Binary Proxy Execution), T1055 (Process Injection),
#     T1204 (User Execution), T1053 (Scheduled Task/Job),
#     T1071 (Application Layer Protocol), T1027 (Obfuscated Files),
#     T1059 (Command and Scripting Interpreter), T1543 (Create/Modify System Process),
#     T1574 (Hijack Execution Flow), T1553 (Subvert Trust Controls),
#     T1547 (Boot/Logon Autostart Execution), T1115 (Clipboard Data),
#     T1562 (Impair Defenses)
#
# Output:
#   Writes <output_dir>/analysis/anomaly_detector.json with all anomaly findings.
# =============================================================================

# Runs all 12 heuristic anomaly checks and writes results to JSON.
# Usage: analyze_anomalies <output_dir>
# Args:
#   output_dir - Root output directory containing raw/ and analysis/ subdirs
# Output:
#   Creates analysis/anomaly_detector.json with all anomaly findings
analyze_anomalies() {
    local output_dir="$1"
    local findings=()

    # Pre-resolve all raw data file paths. Each check guards on file existence,
    # so missing collectors (e.g., no clipboard on headless servers) are handled
    # gracefully rather than producing errors.
    local proc_file="${output_dir}/raw/processes.json"
    local net_file="${output_dir}/raw/network.json"
    local persist_file="${output_dir}/raw/persistence.json"
    local env_file="${output_dir}/raw/environment.json"
    local cert_file="${output_dir}/raw/certificates.json"
    local kmod_file="${output_dir}/raw/kernel_modules.json"
    local clip_file="${output_dir}/raw/clipboard.json"
    local fw_file="${output_dir}/raw/firewall.json"
    local hist_file="${output_dir}/raw/shell_history.json"

    # Helper to append a structured finding to the findings array.
    # Usage: _add_finding <check> <desc> <severity> <technique> <detail>
    # Args:
    #   check     - Short identifier for the heuristic (e.g., "lolbin", "temp_exec")
    #   desc      - Human-readable description of what was detected
    #   severity  - Severity level: low, medium, high, or critical
    #   technique - MITRE ATT&CK technique ID
    #   detail    - Additional context about the finding
    _add_finding() {
        local check="$1" desc="$2" severity="$3" technique="$4" detail="$5"
        findings+=("$(json_object \
            "$(json_kvs "type" "anomaly")" \
            "$(json_kvs "check" "$check")" \
            "$(json_kvs "description" "$desc")" \
            "$(json_kvs "severity" "$severity")" \
            "$(json_kvs "mitre_technique" "$technique")" \
            "$(json_kvs "detail" "$detail")"
        )")
    }

    # ---- Check 1: LOLBins (Living-off-the-Land Binaries) ----
    # Detects legitimate system binaries commonly abused by attackers to proxy
    # execution, download payloads, or bypass application whitelisting.
    # Platform-specific lists are used because Linux and macOS have different
    # sets of abusable binaries (e.g., certutil on Linux vs osascript on macOS).
    # MITRE: T1218 — Signed Binary Proxy Execution
    if [[ -f "$proc_file" ]]; then
        local lolbins=()
        if is_linux; then lolbins=("${LOLBINS_LINUX[@]}"); else lolbins=("${LOLBINS_MACOS[@]}"); fi
        for lolbin in "${lolbins[@]}"; do
            # Quoted grep pattern to match the exact binary name in JSON strings,
            # reducing false positives from partial substring matches
            if grep -q "\"${lolbin}\"" "$proc_file" 2>/dev/null; then
                _add_finding "lolbin" "LOLBin detected: ${lolbin}" "medium" "T1218" "Process ${lolbin} found running"
            fi
        done
    fi

    # ---- Check 2: Unusual Parent-Child Process Patterns ----
    # Searches process command lines for patterns that suggest interactive
    # reverse shells, process injection, or scripted execution from unexpected
    # contexts. "bash -i" indicates an interactive shell (common in reverse
    # shells), while /dev/tcp and /dev/udp are bash built-ins used for network
    # redirection without external tools.
    # MITRE: T1055 — Process Injection
    if [[ -f "$proc_file" ]]; then
        for pattern in "sh -c" "/bin/sh" "bash -i" "bash -c" "/dev/tcp" "/dev/udp"; do
            if grep -q "$pattern" "$proc_file" 2>/dev/null; then
                _add_finding "parent_child" "Suspicious process pattern: ${pattern}" "high" "T1055" "Found pattern in process listing"
            fi
        done
    fi

    # ---- Check 3: Temp Directory Execution ----
    # Flags processes with binaries or working directories in world-writable
    # temp locations. Attackers frequently stage and execute payloads from /tmp
    # or /dev/shm because these directories are writable by any user and often
    # lack monitoring. /dev/shm is especially concerning as it's a tmpfs
    # (RAM-backed) that leaves no disk artifacts.
    # MITRE: T1204 — User Execution
    if [[ -f "$proc_file" ]]; then
        for tmpdir in /tmp /var/tmp /dev/shm; do
            if grep -q "\"${tmpdir}/" "$proc_file" 2>/dev/null; then
                _add_finding "temp_exec" "Process executing from ${tmpdir}" "high" "T1204" "Binary running from temp directory"
            fi
        done
    fi

    # ---- Check 4: Suspicious Scheduled Tasks / Persistence Entries ----
    # Looks for download utilities (curl, wget), netcat variants, inline script
    # interpreters, and encoding tools referenced in persistence mechanisms
    # (crontabs, launchd plists, systemd units). Legitimate scheduled tasks
    # rarely invoke these tools directly; their presence strongly suggests a
    # backdoor or C2 callback. Case-insensitive grep (-qi) catches variations.
    # MITRE: T1053 — Scheduled Task/Job
    if [[ -f "$persist_file" ]]; then
        for susp in "curl " "wget " "nc " "ncat " "bash -c" "/dev/tcp" "base64" "python -c" "perl -e"; do
            if grep -qi "$susp" "$persist_file" 2>/dev/null; then
                _add_finding "susp_schtask" "Suspicious persistence entry containing: ${susp}" "high" "T1053" "Persistence mechanism with suspicious command"
            fi
        done
    fi

    # ---- Check 5: Suspicious Network Ports ----
    # Scans network connection data for ports associated with common C2
    # frameworks, backdoors, and exfiltration channels. The SUSPICIOUS_PORTS
    # array is defined in the project's constants/config and includes ports
    # like 4444 (Metasploit), 1234 (generic backdoor), 8443 (alt HTTPS C2), etc.
    # MITRE: T1071 — Application Layer Protocol
    if [[ -f "$net_file" ]]; then
        for port in "${SUSPICIOUS_PORTS[@]}"; do
            if grep -q ":${port}" "$net_file" 2>/dev/null; then
                _add_finding "susp_port" "Connection to suspicious port: ${port}" "high" "T1071" "Network connection on known-bad port"
            fi
        done
    fi

    # ---- Check 6: Base64-Encoded Commands ----
    # Two-pronged check:
    # a) Looks for long base64 strings (40+ chars) in process arguments. The
    #    40-char threshold balances sensitivity vs. false positives — shorter
    #    base64 strings often appear in legitimate JSON/JWT tokens.
    # b) Checks shell history for explicit base64 decode pipelines, which
    #    indicate a human or script intentionally decoding obfuscated payloads.
    # MITRE: T1027 (Obfuscated Files) for process args,
    #         T1059 (Command and Scripting Interpreter) for shell history
    if [[ -f "$proc_file" ]]; then
        if grep -qE '[A-Za-z0-9+/]{40,}={0,2}' "$proc_file" 2>/dev/null; then
            _add_finding "base64_cmd" "Possible base64-encoded command in process arguments" "high" "T1027" "Long base64 string detected in process command line"
        fi
    fi
    if [[ -f "$hist_file" ]]; then
        if grep -qE 'base64.*-d|echo.*\|.*base64' "$hist_file" 2>/dev/null; then
            _add_finding "base64_hist" "Base64 decode command in shell history" "medium" "T1059" "Shell history contains base64 decoding"
        fi
    fi

    # ---- Check 7: Unusual Services / Daemons ----
    # Flags services or daemons whose configuration references temp directories.
    # Legitimate services almost never have their binaries or configs in /tmp.
    # A service pointing to /tmp is a strong indicator that an attacker installed
    # a persistent backdoor in a world-writable location.
    # MITRE: T1543 — Create or Modify System Process
    if [[ -f "$persist_file" ]]; then
        if grep -qE '(/tmp/|/var/tmp/|/dev/shm/)' "$persist_file" 2>/dev/null; then
            _add_finding "susp_service" "Service/daemon referencing temp directory" "high" "T1543" "Persistence entry points to temp location"
        fi
    fi

    # ---- Check 8: PATH Hijacking ----
    # Detects writable or semantically dangerous directories in $PATH. An
    # attacker who prepends /tmp or "." to PATH can trick privileged scripts
    # into executing attacker-controlled binaries instead of system ones.
    # "::" (empty path component) is equivalent to "." and is equally dangerous.
    # MITRE: T1574 — Hijack Execution Flow
    if [[ -f "$env_file" ]]; then
        for susp_path in "/tmp" "/var/tmp" "/dev/shm" "." "::"; do
            if grep -q "\"PATH\".*\"${susp_path}" "$env_file" 2>/dev/null; then
                _add_finding "path_hijack" "Suspicious directory in PATH: ${susp_path}" "high" "T1574" "PATH contains writable/suspicious directory"
            fi
        done
    fi

    # ---- Check 9: Rogue Certificates ----
    # Self-signed certificates in the system trust store can enable MITM
    # attacks or allow malware to validate against its own certificate chain.
    # Rated "medium" rather than "high" because some dev environments
    # legitimately use self-signed certs — analysts should review the issuers.
    # MITRE: T1553 — Subvert Trust Controls
    if [[ -f "$cert_file" ]]; then
        if grep -q '"is_self_signed": true' "$cert_file" 2>/dev/null; then
            local self_signed_count
            self_signed_count="$(grep -c '"is_self_signed": true' "$cert_file" 2>/dev/null || echo 0)"
            _add_finding "rogue_cert" "${self_signed_count} self-signed certificate(s) detected" "medium" "T1553" "Self-signed certificates in trust store"
        fi
    fi

    # ---- Check 10: Suspicious Kernel Modules ----
    # Scans loaded kernel module names for keywords strongly associated with
    # rootkits and surveillance tools. Rated "critical" because a malicious
    # kernel module has complete control over the system and can hide processes,
    # files, and network connections from userspace tools.
    # MITRE: T1547 — Boot or Logon Autostart Execution
    if [[ -f "$kmod_file" ]]; then
        for susp_mod in "rootkit" "hide" "stealth" "keylog" "sniff"; do
            if grep -qi "$susp_mod" "$kmod_file" 2>/dev/null; then
                _add_finding "susp_kmod" "Suspicious kernel module name containing: ${susp_mod}" "critical" "T1547" "Kernel module with suspicious name"
            fi
        done
    fi

    # ---- Check 11: Clipboard IOCs ----
    # Clipboard content can reveal attacker-pasted commands, C2 URLs, or
    # exfiltrated data. Rated "low" because users commonly copy URLs/IPs
    # for legitimate reasons — this is a lead for analysts, not a definitive
    # indicator by itself.
    # MITRE: T1115 — Clipboard Data
    if [[ -f "$clip_file" ]]; then
        if grep -q '"has_urls": true\|"has_ips": true' "$clip_file" 2>/dev/null; then
            _add_finding "clipboard_ioc" "Clipboard contains URLs or IP addresses" "low" "T1115" "IOC indicators found in clipboard content"
        fi
    fi

    # ---- Check 12: Firewall Tampering ----
    # A disabled host firewall is a common post-exploitation action to allow
    # lateral movement and C2 traffic. This check is deliberately broad
    # (matching "disabled", "inactive", or "off") to catch output variations
    # across iptables, ufw, firewalld, and macOS Application Firewall.
    # MITRE: T1562 — Impair Defenses
    if [[ -f "$fw_file" ]]; then
        if grep -qi "disabled\|inactive\|off" "$fw_file" 2>/dev/null; then
            _add_finding "fw_tamper" "Firewall may be disabled" "high" "T1562" "Firewall status indicates disabled state"
        fi
    fi

    # Assemble and write the final JSON report.
    # The "${findings[@]+"${findings[@]}"}" pattern prevents "unbound variable"
    # errors under set -u when no findings were generated.
    local result
    result="$(json_object \
        "$(json_kvs "analyzer" "anomaly_detector")" \
        "$(json_kvn "finding_count" "${#findings[@]}")" \
        "$(json_kv "findings" "$(json_array "${findings[@]+"${findings[@]}"}")")"
    )"

    json_write "${output_dir}/analysis/anomaly_detector.json" "$result"
    log_info "Anomaly detector: ${#findings[@]} findings"
}
