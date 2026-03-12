#!/usr/bin/env bash
# ============================================================================
# Collector: kernel_modules
# ============================================================================
#
# Purpose:
#   Enumerates loaded kernel modules (Linux) or kernel extensions (macOS).
#   Rootkits and advanced malware often install kernel modules to achieve
#   stealth and persistence at the kernel level. Comparing the loaded module
#   list against a known-good baseline can reveal unauthorized modules.
#
# Artifacts gathered:
#   Linux (per module): module name, size, use count, used-by list, state,
#   memory offset
#   macOS (per kext): index, reference count, address, size, wired memory,
#   bundle identifier, version
#
# Platform support:
#   Linux:
#     - /proc/modules (preferred): direct kernel interface, always available,
#       provides the most detail (size, use count, dependencies, state, offset)
#     - lsmod (fallback): user-space wrapper around /proc/modules with less
#       detail; used when /proc/modules is inaccessible
#   macOS:
#     - kextstat: lists loaded kernel extensions with bundle IDs, versions,
#       reference counts, and memory addresses
#     - Note: modern macOS versions (11+) deprecate kextstat in favor of
#       System Extensions, but kextstat still works for legacy kexts
#
# Performance optimization:
#   Uses awk for bulk JSON generation on all data sources. Kernel module
#   lists can contain 100-200+ entries on typical Linux servers with many
#   driver modules loaded.
#
# Output:
#   JSON array of module/kext artifacts, written via write_collector_result.
# ============================================================================

# collect_kernel_modules — enumerates loaded kernel modules/extensions
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Linux and macOS have completely different kernel module systems:
#     - Linux uses loadable kernel modules (.ko files) managed by modprobe
#     - macOS uses kernel extensions (.kext bundles) managed by kextload
#   The output schemas differ accordingly: Linux modules have use counts
#   and dependency chains, while macOS kexts have bundle IDs and versions.
#
# Performance:
#   awk generates the entire JSON array in a single pass from /proc/modules,
#   lsmod, or kextstat output. The esc() function handles JSON string
#   escaping within awk to avoid external calls.
collect_kernel_modules() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts_json="[]"
    local count=0

    if is_linux; then
        # Prefer /proc/modules over lsmod — it's a direct kernel interface
        # that doesn't require the kmod userspace package to be installed
        if [[ -f /proc/modules ]]; then
            # /proc/modules fields: name, size, use_count, used_by_list, state, offset
            # The used_by list has a trailing comma that is stripped by sub()
            artifacts_json="$(awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            BEGIN { printf "[" }
            NR > 1 { printf ", " }
            {
                used = $4; sub(/,$/, "", used)
                printf "{\"module_name\": \"%s\", \"size\": %s, \"use_count\": %s, \"used_by\": \"%s\", \"state\": \"%s\", \"offset\": \"%s\"}", \
                    esc($1), $2, $3, esc(used), esc($5), esc($6)
            }
            END { printf "]" }
            ' /proc/modules)"
            count="$(wc -l < /proc/modules | tr -d ' ')"
        elif has_cmd lsmod; then
            # lsmod fallback: less detail (no state/offset), header skipped with tail
            artifacts_json="$(lsmod 2>/dev/null | tail -n +2 | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            BEGIN { printf "[" }
            NR > 1 { printf ", " }
            {
                printf "{\"module_name\": \"%s\", \"size\": %s, \"used_by\": \"%s\"}", \
                    esc($1), $2, esc($4)
            }
            END { printf "]" }
            ')"
            count="$(lsmod 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
        fi

    elif is_darwin; then
        # kextstat output has a header line starting with "Index" that is skipped.
        # Parentheses in version strings are stripped by the esc() function.
        # NF >= 6 ensures we only process lines with enough fields for a valid kext.
        if has_cmd kextstat; then
            artifacts_json="$(kextstat 2>/dev/null | awk '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/[()]/, "", s); return s }
            /^Index/ { next }
            NF >= 6 {
                if (count++) printf ", "
                printf "{\"index\": %s, \"refs\": %s, \"address\": \"%s\", \"size\": \"%s\", \"wired\": \"%s\", \"bundle_id\": \"%s\", \"version\": \"%s\"}", \
                    $1, $2, esc($3), esc($4), esc($5), esc($6), esc($7)
            }
            BEGIN { printf "["; count = 0 }
            END { printf "]" }
            ')"
            count="$(kextstat 2>/dev/null | grep -cv '^Index' || echo 0)"
        fi
    fi

    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "kernel_modules" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "kernel_modules" "$result"
}
