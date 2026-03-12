#!/usr/bin/env bash
# ============================================================================
# Collector: usb_devices
# ============================================================================
#
# Purpose:
#   Enumerates USB devices currently attached to the system and historical
#   USB device records. USB device data is critical for detecting unauthorized
#   storage devices (thumb drives used for exfiltration), rubber ducky /
#   BadUSB attacks, and establishing a timeline of physical device access.
#
# Artifacts gathered:
#   Linux:
#     - sysfs entries: vendor ID, product ID, manufacturer, product name,
#       serial number, device path for each USB device
#     - lsusb output: raw device listing for cross-reference
#   macOS:
#     - system_profiler SPUSBDataType: full USB device tree in JSON format
#
# Platform support:
#   Linux:
#     - /sys/bus/usb/devices/*/: kernel sysfs pseudo-filesystem for USB
#       device attributes (always available, no dependencies)
#     - lsusb: user-space USB enumeration tool (optional, from usbutils)
#   macOS:
#     - system_profiler SPUSBDataType -json: native macOS system information
#       tool with JSON output support
#
# Performance optimization:
#   This collector writes JSON directly to a file rather than using the
#   standard write_collector_result path. On macOS, system_profiler outputs
#   a large JSON blob that would be expensive to pass through json_escape
#   (which processes character-by-character). Instead, the raw JSON from
#   system_profiler is embedded directly since it's already valid JSON.
#
# Output:
#   Writes directly to raw/usb_devices.json in the output directory.
#   Uses jq for pretty-printing if available.
# ============================================================================

# collect_usb_devices — enumerates currently attached USB devices
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Linux enumerates USB devices from two sources for completeness:
#     - sysfs provides structured per-device attributes (vendor, product,
#       serial) but only for devices with idVendor files
#     - lsusb provides a compact human-readable listing that may include
#       devices not visible in sysfs
#   macOS uses system_profiler which returns the complete USB device tree
#   including hubs, their children, and detailed device properties.
#
# File I/O strategy:
#   Uses the same direct-to-file pattern as the logs collector. The
#   _append_artifact helper writes comma-separated JSON objects to a temp
#   file, and the final envelope is assembled around it.
collect_usb_devices() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local raw_dir="${output_dir}/raw"
    ensure_dir "$raw_dir"
    local out_file="${raw_dir}/usb_devices.json"
    local tmp_file
    tmp_file="$(mktemp)"

    local artifact_count=0

    # _append_artifact — adds a JSON object to the temp artifacts file
    # with comma separation between entries
    _append_artifact() {
        [[ "$artifact_count" -gt 0 ]] && printf ', ' >> "$tmp_file"
        printf '%s' "$1" >> "$tmp_file"
        artifact_count=$((artifact_count + 1))
    }

    if is_linux; then
        # ── sysfs enumeration ──
        # /sys/bus/usb/devices/ contains one directory per USB device.
        # Only directories with an idVendor file represent actual USB
        # devices (others are hubs, root ports, or interfaces).
        if [[ -d /sys/bus/usb/devices ]]; then
            for dev_dir in /sys/bus/usb/devices/*/; do
                [[ -f "${dev_dir}idVendor" ]] || continue
                local vendor_id product_id manufacturer product serial
                vendor_id="$(cat "${dev_dir}idVendor" 2>/dev/null || echo "")"
                product_id="$(cat "${dev_dir}idProduct" 2>/dev/null || echo "")"
                manufacturer="$(cat "${dev_dir}manufacturer" 2>/dev/null || echo "")"
                product="$(cat "${dev_dir}product" 2>/dev/null || echo "")"
                serial="$(cat "${dev_dir}serial" 2>/dev/null || echo "")"

                _append_artifact "$(json_object \
                    "$(json_kvs "source" "sysfs")" \
                    "$(json_kvs "device_path" "$dev_dir")" \
                    "$(json_kvs "vendor_id" "$vendor_id")" \
                    "$(json_kvs "product_id" "$product_id")" \
                    "$(json_kvs "manufacturer" "$manufacturer")" \
                    "$(json_kvs "product_name" "$product")" \
                    "$(json_kvs "serial_number" "$serial")"
                )"
            done
        fi

        # ── lsusb ──
        # Provides a complementary view; each line is stored as a raw entry
        # since lsusb output format varies across distributions
        if has_cmd lsusb; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                _append_artifact "$(json_object \
                    "$(json_kvs "source" "lsusb")" \
                    "$(json_kvs "raw_entry" "$line")"
                )"
            done < <(lsusb 2>/dev/null)
        fi

    elif is_darwin; then
        # ── system_profiler ──
        # The -json flag produces valid JSON output that can be embedded
        # directly without escaping. This avoids the performance cost of
        # running json_escape on system_profiler's potentially large output
        # (which can include dozens of USB devices with detailed properties).
        if has_cmd system_profiler; then
            local usb_json
            usb_json="$(system_profiler SPUSBDataType -json 2>/dev/null || true)"
            if [[ -n "$usb_json" ]]; then
                printf '{"source": "system_profiler", "raw": %s}' "$usb_json" >> "$tmp_file"
                artifact_count=$((artifact_count + 1))
            fi
        fi
    fi

    local end_ts
    end_ts="$(epoch_now)"
    local duration=$(( end_ts - start_ts ))

    # Assemble final JSON envelope around the accumulated artifacts
    printf '{"collector_name": "usb_devices", "platform": "%s", "hostname": "%s", "collected_at": "%s", "duration_seconds": %d, "artifact_count": %d, "artifacts": [' \
        "$PLATFORM_LOWER" "$(hostname)" "$(utc_now)" "$duration" "$artifact_count" > "$out_file"
    cat "$tmp_file" >> "$out_file"
    printf ']}\n' >> "$out_file"

    rm -f "$tmp_file"

    if has_cmd jq; then
        local pretty
        pretty="$(jq '.' "$out_file" 2>/dev/null)" && printf '%s\n' "$pretty" > "$out_file"
    fi

    audit_log "collector_complete" "Collector usb_devices finished"
}
