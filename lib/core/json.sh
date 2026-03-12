#!/usr/bin/env bash
##############################################################################
# json.sh — Pure-Bash JSON Construction Helpers
##############################################################################
#
# Part of IntrusionInspector (Bash Edition), a DFIR triage toolkit.
#
# PURPOSE:
#   Provides a composable set of functions for building valid JSON strings
#   entirely in Bash, with ZERO external dependencies. This is critical
#   because the tool must run on minimal incident-response boot media and
#   hardened servers where jq, python, or other JSON utilities may not be
#   installed.
#
# ARCHITECTURAL ROLE:
#   Every collector module in lib/collectors/ produces JSON artifacts using
#   these helpers. The analysis engine and report generator also consume
#   JSON produced here. This module is the second-lowest layer (above
#   platform.sh) and is depended upon by logging.sh (for audit_log) and
#   every collector.
#
# DESIGN PHILOSOPHY:
#   - Build JSON by string concatenation in Bash variables. This avoids
#     spawning subprocesses for each field and keeps overhead proportional
#     to artifact count rather than field count.
#   - Use `printf '%s'` (not `echo`) everywhere for consistent behavior
#     across Bash versions and to avoid interpreting escape sequences.
#   - The json_escape function handles the JSON spec's required escapes
#     (backslash, double-quote, newline, carriage return, tab) plus strips
#     any remaining ASCII control characters that would produce invalid JSON.
#   - jq is used opportunistically for pretty-printing output files, but
#     the module never *requires* jq for correctness.
#
# BASH 3.x COMPATIBILITY:
#   All string manipulations use ${var//pattern/replacement} which is
#   available in Bash 3.2+. We avoid associative arrays (Bash 4+) and
#   nameref variables (Bash 4.3+).
#
# FUNCTIONS:
#   json_escape          — escape a raw string for embedding in JSON
#   json_str             — wrap a value as a JSON string
#   json_num             — pass through a numeric value unquoted
#   json_bool            — normalise a value to JSON true/false
#   json_null            — emit a JSON null literal
#   json_kv              — build "key": <raw_value> pair
#   json_kvs             — build "key": "string_value" pair
#   json_kvn             — build "key": number pair
#   json_kvb             — build "key": boolean pair
#   json_object          — assemble pairs into a JSON object
#   json_array           — assemble elements into a JSON array
#   json_array_from_lines — stream-build an array from stdin
#   json_pretty          — pretty-print via jq if available
#   json_write           — write JSON content to a file
#
##############################################################################

# -------------------------------------------------------------------
# Source guard: prevent double-loading in complex dependency chains
# where multiple collectors source utils.sh which sources json.sh.
# -------------------------------------------------------------------
_JSON_LOADED=${_JSON_LOADED:-false}
[[ "$_JSON_LOADED" == "true" ]] && return 0
_JSON_LOADED=true

# Escape a raw string so it is safe to embed inside a JSON string literal.
#
# Handles the mandatory JSON escapes per RFC 8259 §7:
#   \\   → \\\\    (backslash)
#   \"   → \\\"    (double-quote)
#   \n   → \\n     (newline)
#   \r   → \\r     (carriage return)
#   \t   → \\t     (tab)
#
# After the targeted replacements, `tr` strips any remaining ASCII control
# characters (0x00–0x08, 0x0B, 0x0C, 0x0E–0x1F). This costs one subprocess
# but is necessary because forensic data (e.g., binary fragments in shell
# history) can contain arbitrary bytes that would break JSON parsers.
#
# Args:
#   $1 — the raw string to escape
# Returns: prints the escaped string to stdout (without surrounding quotes).
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
    printf '%s' "$s"
}

# Wrap a value as a double-quoted JSON string: "value".
# The value is escaped before quoting.
# Args:
#   $1 — the raw string value
# Returns: prints the quoted, escaped JSON string to stdout.
json_str() {
    printf '"%s"' "$(json_escape "$1")"
}

# Emit a JSON number (unquoted).
# No validation is performed — the caller must ensure the value is numeric.
# Keeping it unvalidated avoids subprocess overhead in hot loops where
# collectors emit thousands of artifacts.
# Args:
#   $1 — the numeric value
# Returns: prints the raw number to stdout.
json_num() {
    printf '%s' "$1"
}

# Normalise a value to a JSON boolean literal.
# Accepts "true" or "1" as truthy; everything else is false.
# Args:
#   $1 — the value to interpret as boolean
# Returns: prints "true" or "false" to stdout.
json_bool() {
    if [[ "$1" == "true" || "$1" == "1" ]]; then
        printf 'true'
    else
        printf 'false'
    fi
}

# Emit a JSON null literal.
# Takes no arguments. Used for optional fields that have no value.
# Returns: prints "null" to stdout.
json_null() {
    printf 'null'
}

# Build a JSON key-value pair where the value is already formatted.
# Use this when the value is a pre-built JSON fragment (object, array, etc.).
# Args:
#   $1 — the key (will be escaped)
#   $2 — the pre-formatted JSON value (used verbatim)
# Returns: prints '"key": value' to stdout.
json_kv() {
    printf '"%s": %s' "$(json_escape "$1")" "$2"
}

# Build a JSON key-value pair where the value is a string.
# Both key and value are escaped. This is the most commonly used helper
# in collectors since most forensic fields are strings.
# Args:
#   $1 — the key
#   $2 — the string value
# Returns: prints '"key": "value"' to stdout.
json_kvs() {
    printf '"%s": "%s"' "$(json_escape "$1")" "$(json_escape "$2")"
}

# Build a JSON key-value pair where the value is a number.
# The key is escaped; the numeric value is used verbatim.
# Args:
#   $1 — the key
#   $2 — the numeric value
# Returns: prints '"key": number' to stdout.
json_kvn() {
    printf '"%s": %s' "$(json_escape "$1")" "$2"
}

# Build a JSON key-value pair where the value is a boolean.
# The key is escaped; the value is normalised via json_bool.
# Args:
#   $1 — the key
#   $2 — the value to interpret as boolean ("true"/"1" → true, else false)
# Returns: prints '"key": true' or '"key": false' to stdout.
json_kvb() {
    printf '"%s": %s' "$(json_escape "$1")" "$(json_bool "$2")"
}

# Assemble pre-formatted key-value pairs into a JSON object.
# Each argument should be a string like '"key": value' (as returned by
# json_kv, json_kvs, etc.). Pairs are comma-separated automatically.
#
# Performance note: string concatenation with += in a loop is O(n²) in
# theory, but in practice the number of fields per object is small (~10-20)
# so this is negligible compared to the I/O cost of reading forensic data.
#
# Usage: json_object '"key1": "val1"' '"key2": 42'
# Args:
#   $@ — one or more pre-formatted key-value pair strings
# Returns: prints the complete JSON object to stdout.
json_object() {
    local result="{"
    local first=true
    for pair in "$@"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            result+=", "
        fi
        result+="$pair"
    done
    result+="}"
    printf '%s' "$result"
}

# Assemble pre-formatted JSON elements into a JSON array.
# Each argument should be a complete JSON value (string, number, object, etc.).
#
# Usage: json_array '{"a":1}' '{"b":2}'
# Args:
#   $@ — one or more pre-formatted JSON value strings
# Returns: prints the complete JSON array to stdout.
json_array() {
    local result="["
    local first=true
    for elem in "$@"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            result+=", "
        fi
        result+="$elem"
    done
    result+="]"
    printf '%s' "$result"
}

# Build a JSON array by reading one JSON element per line from stdin.
# Blank lines are skipped. This is useful for piping command output through
# a transformation and collecting results without storing them in a Bash
# array (which has size limits and quoting pitfalls in Bash 3.x).
#
# Usage: some_command | while read ...; do json_object ...; done | json_array_from_lines
# Returns: prints the complete JSON array to stdout.
json_array_from_lines() {
    local result="["
    local first=true
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$first" == "true" ]]; then
            first=false
        else
            result+=", "
        fi
        result+="$line"
    done
    result+="]"
    printf '%s' "$result"
}

# Pretty-print JSON from stdin using jq if available.
# Falls back to passthrough (`cat`) on systems without jq. The jq call
# is wrapped in `|| cat` so a malformed JSON input doesn't crash the
# pipeline — it just passes through un-prettified.
# Returns: prints formatted (or raw) JSON to stdout.
json_pretty() {
    if command -v jq &>/dev/null; then
        jq '.' 2>/dev/null || cat
    else
        cat
    fi
}

# Write a JSON string to a file, pretty-printing via jq when available.
# If jq fails (e.g., input is too large or malformed), falls back to
# writing the raw JSON string directly. A trailing newline is always
# appended to comply with POSIX text-file conventions.
# Args:
#   $1 — destination file path
#   $2 — the JSON content string
json_write() {
    local file="$1"
    local content="$2"
    if command -v jq &>/dev/null; then
        printf '%s' "$content" | jq '.' > "$file" 2>/dev/null || printf '%s\n' "$content" > "$file"
    else
        printf '%s\n' "$content" > "$file"
    fi
}
