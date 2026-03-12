#!/usr/bin/env bash
##############################################################################
# platform.sh — Platform Detection & Cross-Platform Command Wrappers
##############################################################################
#
# Part of IntrusionInspector (Bash Edition), a DFIR triage toolkit.
#
# PURPOSE:
#   Provides a unified abstraction layer over the fundamental differences
#   between macOS (Darwin) and Linux (Debian/Ubuntu, RHEL/CentOS/Fedora).
#   Every other module in the project sources this file so it can call
#   file-hashing, stat, and date functions without caring which OS it runs on.
#
# ARCHITECTURAL ROLE:
#   This is the lowest-level module in the dependency graph — it has NO
#   internal dependencies on other lib/core modules. All modules that touch
#   the filesystem or produce timestamps depend on platform.sh.
#
# KEY DESIGN DECISIONS:
#   - `stat`, `date`, `sha256sum/shasum`, and `md5sum/md5` have incompatible
#     flag sets between GNU (Linux) and BSD (macOS). Rather than scattering
#     if/else blocks throughout every collector, we centralise them here.
#   - `uname -s` is POSIX and works identically on every target platform.
#   - We use `tr '[:upper:]' '[:lower:]'` instead of Bash 4's ${,,} operator
#     because macOS ships with Bash 3.2 and the lowercasing operator is a
#     Bash 4+ feature.
#   - All hash/stat helpers suppress stderr (2>/dev/null) so callers get a
#     clean empty string on failure rather than noisy error messages.
#
# EXPORTED GLOBALS:
#   PLATFORM        — raw `uname -s` output ("Linux" or "Darwin")
#   PLATFORM_LOWER  — lowercase variant for filenames and JSON fields
#   PKG_MANAGER     — "brew", "dpkg", "rpm", or "unknown"
#
# FUNCTIONS:
#   is_linux, is_darwin            — boolean platform tests
#   detect_pkg_manager             — identify the system package manager
#   has_cmd                        — check if a command exists in PATH
#   compute_sha256, compute_md5    — hash a file
#   file_size, file_mtime, file_perms — stat wrappers
#   epoch_to_iso, utc_now, epoch_now  — timestamp helpers
#
##############################################################################

# -------------------------------------------------------------------
# Source guard: prevent double-loading when multiple modules source us.
# Uses string comparison ("true"/"false") instead of integer flags for
# clarity and to avoid issues with unset-variable checks under `set -u`.
# -------------------------------------------------------------------
_PLATFORM_LOADED=${_PLATFORM_LOADED:-false}
[[ "$_PLATFORM_LOADED" == "true" ]] && return 0
_PLATFORM_LOADED=true

# -------------------------------------------------------------------
# Platform identity — resolved once at load time so every subsequent
# call is a cheap string comparison rather than a subprocess fork.
# -------------------------------------------------------------------
PLATFORM="$(uname -s)"
PLATFORM_LOWER="$(echo "$PLATFORM" | tr '[:upper:]' '[:lower:]')"

# Test whether the current OS is Linux.
# Returns: 0 (true) if Linux, 1 (false) otherwise.
is_linux()  { [[ "$PLATFORM" == "Linux" ]]; }

# Test whether the current OS is macOS (Darwin).
# Returns: 0 (true) if macOS, 1 (false) otherwise.
is_darwin() { [[ "$PLATFORM" == "Darwin" ]]; }

# Detect the system package manager.
# Used by collectors that need to enumerate installed packages. The order
# of checks matters on Linux: dpkg is tested before rpm because some
# systems (e.g., Ubuntu) have both, but dpkg is the canonical source.
# Returns: prints one of "brew", "dpkg", "rpm", or "unknown" to stdout.
detect_pkg_manager() {
    if is_darwin; then
        echo "brew"
    elif command -v dpkg &>/dev/null; then
        echo "dpkg"
    elif command -v rpm &>/dev/null; then
        echo "rpm"
    else
        echo "unknown"
    fi
}

# Resolved at source time so collectors don't re-detect on every call.
PKG_MANAGER="$(detect_pkg_manager)"

# Check whether a command exists in PATH.
# Uses `command -v` (POSIX) rather than `which` (non-portable).
# Args:
#   $1 — command name to look up
# Returns: 0 if found, 1 if not.
has_cmd() { command -v "$1" &>/dev/null; }

# Compute the SHA-256 hash of a file.
# Linux provides `sha256sum` (coreutils); macOS uses `shasum -a 256`
# (part of the Perl distribution bundled with macOS). Both print the
# hash followed by the filename, so we awk out just the hash.
# Args:
#   $1 — path to the file
# Returns: prints the 64-character hex digest to stdout, or nothing on error.
compute_sha256() {
    local file="$1"
    if is_linux; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    else
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    fi
}

# Compute the MD5 hash of a file.
# Linux has `md5sum` (coreutils); macOS has `md5 -q` (BSD md5 with quiet
# flag to suppress the filename prefix). MD5 is used alongside SHA-256
# for compatibility with IOC feeds that publish MD5-only indicators.
# Args:
#   $1 — path to the file
# Returns: prints the 32-character hex digest to stdout, or nothing on error.
compute_md5() {
    local file="$1"
    if is_linux; then
        md5sum "$file" 2>/dev/null | awk '{print $1}'
    else
        md5 -q "$file" 2>/dev/null
    fi
}

# Get the size of a file in bytes.
# GNU stat uses `-c '%s'` for format strings; BSD stat uses `-f '%z'`.
# This is one of the most commonly hit cross-platform divergences.
# Args:
#   $1 — path to the file
# Returns: prints the size in bytes to stdout, or nothing on error.
file_size() {
    local file="$1"
    if is_linux; then
        stat -c '%s' "$file" 2>/dev/null
    else
        stat -f '%z' "$file" 2>/dev/null
    fi
}

# Get the last-modification time of a file as a Unix epoch.
# GNU stat: `-c '%Y'` gives mtime as seconds since epoch.
# BSD stat: `-f '%m'` gives the same value.
# Args:
#   $1 — path to the file
# Returns: prints the epoch timestamp to stdout, or nothing on error.
file_mtime() {
    local file="$1"
    if is_linux; then
        stat -c '%Y' "$file" 2>/dev/null
    else
        stat -f '%m' "$file" 2>/dev/null
    fi
}

# Get a file's permission bits in octal (e.g., "755").
# GNU stat: `-c '%a'` prints the octal mode.
# BSD stat: `-f '%Lp'` prints the low permission bits in octal. The 'L'
# modifier strips the file-type bits, and 'p' selects octal output.
# Args:
#   $1 — path to the file
# Returns: prints the octal permission string to stdout.
file_perms() {
    local file="$1"
    if is_linux; then
        stat -c '%a' "$file" 2>/dev/null
    else
        stat -f '%Lp' "$file" 2>/dev/null
    fi
}

# Convert a Unix epoch timestamp to an ISO-8601 UTC string.
# GNU date: `-d "@epoch"` parses epoch input.
# BSD date: `-r epoch` interprets the argument as an epoch.
# Both use `-u` for UTC and the same strftime format string.
# Args:
#   $1 — Unix epoch timestamp (seconds since 1970-01-01T00:00:00Z)
# Returns: prints an ISO-8601 string like "2024-06-15T12:34:56Z" to stdout.
epoch_to_iso() {
    local epoch="$1"
    if is_linux; then
        date -u -d "@${epoch}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
    else
        date -u -r "${epoch}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
    fi
}

# Get the current UTC timestamp in ISO-8601 format.
# This is platform-agnostic because `date -u` and `strftime` format
# specifiers are consistent across GNU and BSD date implementations.
# Returns: prints a string like "2024-06-15T12:34:56Z" to stdout.
utc_now() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

# Get the current time as a Unix epoch (seconds since 1970-01-01).
# `date +%s` is supported by both GNU and BSD date.
# Returns: prints the epoch as an integer to stdout.
epoch_now() {
    date +%s
}
