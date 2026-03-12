#!/usr/bin/env bash
##############################################################################
# config.sh — Configuration Constants & Detection Signatures
##############################################################################
#
# Part of IntrusionInspector (Bash Edition), a DFIR triage toolkit.
#
# PURPOSE:
#   Centralises every tunable parameter, detection signature, and
#   platform-specific path into a single source of truth. Collectors
#   and analyzers import these constants rather than hardcoding values,
#   which keeps the rest of the codebase DRY and makes it easy to
#   adjust thresholds, add new LOLBins, or support new platforms.
#
# ARCHITECTURAL ROLE:
#   Loaded early in the startup sequence (after platform.sh and json.sh).
#   Has no internal dependencies — only references environment variables
#   and Bash builtins. Profiles (lib/profiles/*.sh) may override some of
#   these values after config.sh is loaded.
#
# BASH 3.x COMPATIBILITY:
#   - Indexed arrays are Bash 3.2+ safe and used heavily here.
#   - Associative arrays are NOT available in Bash 3.x, so parent→child
#     process mappings and severity weights use `case` functions instead.
#   - SUSPICIOUS_PARENTS is a space-delimited string (not an array) so
#     it can be iterated with a simple `for p in $SUSPICIOUS_PARENTS`.
#
# CUSTOMISATION:
#   Several values can be overridden via environment variables before the
#   tool is invoked (e.g., II_OUTPUT_DIR, II_CASE_ID, II_EXAMINER).
#   Collection profiles can further narrow or expand these defaults.
#
##############################################################################

# -------------------------------------------------------------------
# Source guard.
# -------------------------------------------------------------------
_CONFIG_LOADED=${_CONFIG_LOADED:-false}
[[ "$_CONFIG_LOADED" == "true" ]] && return 0
_CONFIG_LOADED=true

# Tool version — follows semver. Embedded in every output report for
# reproducibility (knowing which version of signatures were used).
VERSION="0.1.0"

# -------------------------------------------------------------------
# Collection limits.
# These guard against runaway I/O during triage. Hashing a multi-GB
# database dump would stall the tool, so MAX_FILE_HASH_SIZE caps it.
# History and log day limits keep the artifact set focused on the
# likely intrusion window.
# -------------------------------------------------------------------
MAX_FILE_HASH_SIZE=$((100 * 1024 * 1024))  # 100 MB
BROWSER_HISTORY_DAYS=30
LOG_COLLECTION_DAYS=7
TEMP_DIR_SCAN_DEPTH=3

# -------------------------------------------------------------------
# Runtime defaults.
# II_OUTPUT_DIR, II_CASE_ID, and II_EXAMINER can be set as environment
# variables before invocation to integrate with external case-management
# workflows. If unset, OUTPUT_DIR defaults to ./output relative to CWD.
# -------------------------------------------------------------------
DEFAULT_PROFILE="standard"
OUTPUT_DIR="${II_OUTPUT_DIR:-./output}"
CASE_ID="${II_CASE_ID:-}"
EXAMINER="${II_EXAMINER:-}"

# -------------------------------------------------------------------
# Suspicious network ports.
# These are commonly associated with reverse shells, C2 frameworks,
# and Tor relays. The network collector flags active connections on
# these ports as potential indicators of compromise.
#   4444/5555   — Metasploit/reverse shell defaults
#   1337/31337  — traditional hacker "leet" ports
#   6666/6667   — IRC (botnet C2)
#   9001/9050/9150 — Tor ORPort / SOCKSPort
# -------------------------------------------------------------------
SUSPICIOUS_PORTS=(4444 5555 8888 1337 31337 6666 6667 9001 9050 9150)

# -------------------------------------------------------------------
# LOLBins (Living Off The Land Binaries) — Linux.
# Legitimate system binaries that attackers abuse for downloading
# payloads, establishing tunnels, or executing code without dropping
# custom malware. The process collector cross-references running
# processes against this list. Grouped by function:
#   Row 1: downloaders/interpreters
#   Row 2: shells and network tools
#   Row 3: text processors and encoding tools
#   Row 4: execution/persistence helpers
#   Row 5-6: compilers, debuggers, remote access, and misc utilities
# -------------------------------------------------------------------
LOLBINS_LINUX=(
    curl wget python python3 perl ruby php
    nc ncat netcat socat bash sh dash zsh
    awk gawk nawk sed openssl base64 xxd
    xterm nohup screen tmux at busybox env
    find ftp gcc gdb git lua make man
    nice node rsync scp sftp ssh strace
    tar taskset tclsh telnet vim xargs
)

# -------------------------------------------------------------------
# LOLBins — macOS.
# Similar concept to the Linux list but includes macOS-specific tools:
#   osascript  — AppleScript execution (used for social-engineering popups)
#   open       — can launch apps or URLs from command line
#   security   — keychain access tool (credential theft)
#   dscl       — directory service CLI (user enumeration)
#   launchctl  — persistence via launch daemons/agents
#   pbcopy/pbpaste — clipboard access (data exfiltration)
#   mdfind/mdls    — Spotlight queries (reconnaissance)
# -------------------------------------------------------------------
LOLBINS_MACOS=(
    curl wget python3 perl ruby php
    nc ncat bash sh zsh osascript
    open say screencapture sqlite3 tclsh
    awk sed openssl base64 pbcopy pbpaste
    security dscl defaults launchctl plutil
    xattr mdls mdfind sips qlmanage
)

# -------------------------------------------------------------------
# Suspicious parent→child process relationships.
#
# These patterns are primarily relevant when analysing process trees
# from Windows endpoints (useful if IntrusionInspector parses imported
# process dumps), but the framework is extensible for Unix patterns.
#
# Implemented as a space-delimited string + case function rather than
# an associative array because Bash 3.x (macOS default) lacks
# associative arrays. The _suspicious_children function acts as a
# lookup table: given a parent name, it returns the suspicious child
# process names.
# -------------------------------------------------------------------
SUSPICIOUS_PARENTS="svchost.exe explorer.exe wmiprvse.exe services.exe w3wp.exe"

# Look up suspicious child processes for a given parent process name.
# Args:
#   $1 — parent process name (e.g., "svchost.exe")
# Returns: prints a space-delimited list of suspicious child names to stdout.
_suspicious_children() {
    case "$1" in
        svchost.exe)  echo "cmd.exe powershell.exe pwsh.exe whoami.exe net.exe" ;;
        explorer.exe) echo "powershell.exe pwsh.exe cmd.exe" ;;
        wmiprvse.exe) echo "cmd.exe powershell.exe pwsh.exe" ;;
        services.exe) echo "cmd.exe powershell.exe" ;;
        w3wp.exe)     echo "cmd.exe powershell.exe whoami.exe" ;;
    esac
}

# -------------------------------------------------------------------
# Suspicious environment variables.
# These variables, when set unexpectedly, can indicate:
#   - Proxy pivoting (http_proxy, socks_proxy, all_proxy)
#   - Library injection / hooking (LD_PRELOAD, DYLD_INSERT_LIBRARIES)
#   - Interpreter startup hijacking (PYTHONSTARTUP, PERL5OPT, RUBYOPT)
#   - Classpath manipulation (CLASSPATH, NODE_OPTIONS)
# The environment collector flags any of these that are set in user
# or system environment.
# -------------------------------------------------------------------
SUSPICIOUS_ENV_VARS=(
    http_proxy https_proxy socks_proxy all_proxy
    LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES
    DYLD_LIBRARY_PATH PYTHONSTARTUP PERL5OPT
    RUBYOPT NODE_OPTIONS CLASSPATH
    COMSPEC PROMPT
)

# -------------------------------------------------------------------
# Risk score weights.
# The analysis engine assigns a severity to each finding and converts
# it to a weighted numeric score. These weights are tuned so that a
# single critical finding (40) immediately dominates the score, while
# low/info findings only matter when they accumulate.
#
# Implemented as a case function for Bash 3.x compatibility (no
# associative arrays).
# -------------------------------------------------------------------

# Map a severity name to its numeric risk weight.
# Args:
#   $1 — severity level: "critical", "high", "medium", "low", or "info"
# Returns: prints the numeric weight to stdout.
_severity_weight() {
    case "$1" in
        critical) echo 40 ;;
        high)     echo 20 ;;
        medium)   echo 10 ;;
        low)      echo 3 ;;
        info)     echo 1 ;;
        *)        echo 0 ;;
    esac
}

# Cap for the composite risk score. Prevents runaway scores when many
# low-severity findings accumulate beyond a meaningful threshold.
MAX_RISK_SCORE=100

# -------------------------------------------------------------------
# Temporary directories to scan per platform.
# Attackers frequently stage payloads in world-writable temp dirs.
# /dev/shm is Linux-only (tmpfs backed by RAM — no disk forensics trail).
# -------------------------------------------------------------------
TEMP_DIRS_LINUX=(/tmp /var/tmp /dev/shm)
TEMP_DIRS_MACOS=(/tmp /var/tmp)

# -------------------------------------------------------------------
# System log file paths per platform.
# Not all files exist on every distribution:
#   - /var/log/syslog — Debian/Ubuntu
#   - /var/log/messages — RHEL/CentOS/Fedora
#   - /var/log/auth.log — Debian/Ubuntu auth events
#   - /var/log/secure — RHEL/CentOS/Fedora auth events
# Collectors iterate this list and silently skip missing files.
# -------------------------------------------------------------------
LOG_FILES_LINUX=(/var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log)
LOG_FILES_MACOS=(/var/log/system.log /var/log/install.log)

# -------------------------------------------------------------------
# Browser history database paths (relative to user home directory).
# These are SQLite databases. The browser history collector copies them
# to a temp location before querying (browsers hold write locks on the
# live files).
#
# Firefox uses a glob because profile directory names contain random
# characters (e.g., "a1b2c3d4.default-release").
# -------------------------------------------------------------------
CHROME_HISTORY_LINUX=".config/google-chrome/Default/History"
CHROME_HISTORY_MACOS="Library/Application Support/Google/Chrome/Default/History"
FIREFOX_GLOB_LINUX=".mozilla/firefox/*/places.sqlite"
FIREFOX_GLOB_MACOS="Library/Application Support/Firefox/Profiles/*/places.sqlite"
SAFARI_HISTORY_MACOS="Library/Safari/History.db"

# -------------------------------------------------------------------
# Shell history files (relative to user home directory).
# Checked for command-line reconnaissance, credential exposure, and
# evidence of attacker commands.
# Fish shell uses a non-dotfile path under .local/share/.
# -------------------------------------------------------------------
SHELL_HISTORY_FILES=(.bash_history .zsh_history .sh_history)
FISH_HISTORY_SUBPATH=".local/share/fish/fish_history"

# -------------------------------------------------------------------
# Certificate store paths.
# Rogue CA certificates are a sign of MITM interception. The cert
# collector enumerates and hashes certificates in these directories.
# macOS certificates live in keychains (binary format) instead of
# PEM/CRT files, so they use a separate lookup.
# -------------------------------------------------------------------
CERT_DIRS_LINUX=(/etc/ssl/certs /usr/local/share/ca-certificates)
CERT_EXTENSIONS=("*.pem" "*.crt")

KEYCHAINS_MACOS=("/Library/Keychains/System.keychain")

# -------------------------------------------------------------------
# Persistence mechanism paths.
# These are the primary locations where attackers install backdoors:
#   - Cron directories (Linux scheduled tasks)
#   - Systemd unit files (Linux service persistence)
#   - LaunchDaemons/LaunchAgents (macOS service persistence)
# User-level LaunchAgents (~/Library/LaunchAgents) are handled
# separately by iterating user home directories.
# -------------------------------------------------------------------
CRON_DIRS_LINUX=(/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly)
SYSTEMD_DIRS=(/etc/systemd/system /usr/lib/systemd/system)
LAUNCHD_DIRS_MACOS=(/Library/LaunchDaemons /Library/LaunchAgents /System/Library/LaunchDaemons)

# -------------------------------------------------------------------
# Anomaly detection patterns.
# Base64-encoded payloads in process command lines are a strong
# indicator of obfuscated malware execution (e.g., `bash -c "$(echo
# <base64> | base64 -d)"`). The regex requires at least 40 base64
# characters to reduce false positives from short legitimate values.
# -------------------------------------------------------------------
ANOMALY_BASE64_PATTERN='([A-Za-z0-9+/]{40,}={0,2})'
