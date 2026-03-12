#!/usr/bin/env bash
# ============================================================================
# Collector: certificates
# ============================================================================
#
# Purpose:
#   Enumerates certificates from system certificate stores. Certificate
#   data is important for DFIR because attackers may install rogue CA
#   certificates to intercept TLS traffic (MITM), self-signed certificates
#   for C2 communication, or malicious code-signing certificates.
#   Self-signed certificates are flagged since they are a common indicator
#   of unauthorized certificate installation.
#
# Artifacts gathered:
#   Per certificate: subject, issuer, serial number, SHA-256 fingerprint,
#   validity period (not_before/not_after), self-signed flag, store name,
#   and source file path.
#
# Platform support:
#   Linux:
#     - CERT_DIRS_LINUX (e.g., /etc/ssl/certs, /etc/pki/tls/certs,
#       /usr/local/share/ca-certificates): standard certificate directories
#     - CERT_EXTENSIONS (e.g., *.pem, *.crt, *.cer): file type filters
#     - find with -maxdepth 2 and head -200 per directory to bound scan time
#     - openssl x509 for certificate parsing
#   macOS:
#     - KEYCHAINS_MACOS (e.g., /System/Library/Keychains/SystemRootCertificates.keychain,
#       /Library/Keychains/System.keychain): system keychain databases
#     - User login keychain (~/Library/Keychains/login.keychain-db)
#     - security find-certificate -a -p: exports all certs as PEM from keychains
#     - openssl x509 for certificate parsing (same as Linux)
#
# Dependencies:
#   Requires openssl for certificate parsing. The _parse_cert helper
#   returns early if openssl is unavailable.
#
# Output:
#   JSON array of certificate artifacts, written via write_collector_result.
# ============================================================================

# collect_certificates — enumerates certificates from system stores
#
# Parameters:
#   $1 (output_dir) — directory where the collector JSON result is written
#
# Cross-platform behavior:
#   Certificate storage differs fundamentally between platforms:
#     - Linux stores certificates as individual PEM/CRT files in well-known
#       directories; they can be parsed directly by openssl
#     - macOS stores certificates in keychain databases (binary format);
#       they must be exported to PEM with the security command before
#       openssl can parse them
#
# Self-signed detection:
#   A certificate is flagged as self-signed if subject == issuer. This is
#   a simple heuristic that catches the most common case. Note that some
#   legitimate root CAs are self-signed by definition — the flag is an
#   indicator, not a definitive verdict.
collect_certificates() {
    local output_dir="$1"
    local start_ts
    start_ts="$(epoch_now)"

    local artifacts=()

    # _parse_cert — extracts metadata from a single PEM certificate file
    #
    # Parameters:
    #   $1 (cert_path)   — path to a PEM-format certificate file
    #   $2 (store_name)  — identifier for the certificate store/directory
    #
    # Requires openssl; returns 1 if openssl is not available.
    # Each openssl invocation extracts a single field to avoid complex
    # output parsing. The self-signed check compares subject to issuer
    # string equality.
    _parse_cert() {
        local cert_path="$1"
        local store_name="$2"

        if ! has_cmd openssl; then
            return 1
        fi

        local subject issuer serial not_before not_after fingerprint
        subject="$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null | sed 's/^subject=//' || echo "")"
        issuer="$(openssl x509 -in "$cert_path" -noout -issuer 2>/dev/null | sed 's/^issuer=//' || echo "")"
        serial="$(openssl x509 -in "$cert_path" -noout -serial 2>/dev/null | sed 's/^serial=//' || echo "")"
        not_before="$(openssl x509 -in "$cert_path" -noout -startdate 2>/dev/null | sed 's/^notBefore=//' || echo "")"
        not_after="$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || echo "")"
        fingerprint="$(openssl x509 -in "$cert_path" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' || echo "")"

        # Self-signed detection: subject matching issuer indicates the cert
        # signed itself. Legitimate for root CAs, suspicious for others.
        local is_self_signed="false"
        [[ "$subject" == "$issuer" ]] && is_self_signed="true"

        artifacts+=("$(json_object \
            "$(json_kvs "subject" "$subject")" \
            "$(json_kvs "issuer" "$issuer")" \
            "$(json_kvs "serial_number" "$serial")" \
            "$(json_kvs "thumbprint" "$fingerprint")" \
            "$(json_kvs "not_before" "$not_before")" \
            "$(json_kvs "not_after" "$not_after")" \
            "$(json_kvb "is_self_signed" "$is_self_signed")" \
            "$(json_kvs "store_name" "$store_name")" \
            "$(json_kvs "file" "$cert_path")"
        )")
    }

    if is_linux; then
        # ── Linux certificate directories ──
        # Iterate through standard cert directories, scanning for files
        # matching known certificate extensions (*.pem, *.crt, *.cer).
        # find is capped at depth 2 and 200 files per directory to bound
        # the number of openssl invocations on systems with large cert stores.
        for cert_dir in "${CERT_DIRS_LINUX[@]}"; do
            [[ -d "$cert_dir" ]] || continue
            for ext in "${CERT_EXTENSIONS[@]}"; do
                while IFS= read -r cert_file; do
                    [[ -f "$cert_file" ]] || continue
                    _parse_cert "$cert_file" "$cert_dir"
                done < <(find "$cert_dir" -maxdepth 2 -name "$ext" -type f 2>/dev/null | head -200)
            done
        done

    elif is_darwin; then
        # ── macOS keychains ──
        # macOS stores certificates in binary keychain databases.
        # security find-certificate -a -p exports all certificates from
        # a keychain as a concatenated PEM bundle. Each cert must be
        # extracted individually (delimited by BEGIN/END CERTIFICATE
        # markers) and written to a temp file for openssl parsing.
        if has_cmd security; then
            for keychain in "${KEYCHAINS_MACOS[@]}"; do
                [[ -f "$keychain" ]] || continue

                local pem_bundle
                pem_bundle="$(security find-certificate -a -p "$keychain" 2>/dev/null || true)"
                [[ -z "$pem_bundle" ]] && continue

                local tmp_cert
                tmp_cert="$(mktemp)"

                # Parse the PEM bundle by tracking BEGIN/END CERTIFICATE markers.
                # Each individual cert is written to a temp file, parsed, then
                # the temp file is overwritten for the next cert.
                local in_cert=false
                local cert_count=0
                while IFS= read -r line; do
                    if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                        in_cert=true
                        echo "$line" > "$tmp_cert"
                    elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                        echo "$line" >> "$tmp_cert"
                        in_cert=false
                        cert_count=$((cert_count + 1))
                        # Cap at 200 certs per keychain to prevent excessive
                        # openssl invocations on the system root keychain
                        # (which may contain 150+ CA certs)
                        [[ "$cert_count" -gt 200 ]] && break
                        _parse_cert "$tmp_cert" "$keychain"
                    elif [[ "$in_cert" == "true" ]]; then
                        echo "$line" >> "$tmp_cert"
                    fi
                done <<< "$pem_bundle"

                rm -f "$tmp_cert"
            done

            # ── User login keychain ──
            # The login keychain may contain user-installed certificates
            # (including potentially malicious ones). Processed identically
            # to system keychains.
            local login_kc="${HOME}/Library/Keychains/login.keychain-db"
            if [[ -f "$login_kc" ]]; then
                local pem_bundle
                pem_bundle="$(security find-certificate -a -p "$login_kc" 2>/dev/null || true)"
                if [[ -n "$pem_bundle" ]]; then
                    local tmp_cert
                    tmp_cert="$(mktemp)"
                    local in_cert=false
                    while IFS= read -r line; do
                        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
                            in_cert=true
                            echo "$line" > "$tmp_cert"
                        elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
                            echo "$line" >> "$tmp_cert"
                            in_cert=false
                            _parse_cert "$tmp_cert" "$login_kc"
                        elif [[ "$in_cert" == "true" ]]; then
                            echo "$line" >> "$tmp_cert"
                        fi
                    done <<< "$pem_bundle"
                    rm -f "$tmp_cert"
                fi
            fi
        fi
    fi

    local count=${#artifacts[@]}
    local artifacts_json
    artifacts_json="$(json_array "${artifacts[@]+"${artifacts[@]}"}")"
    local end_ts
    end_ts="$(epoch_now)"

    local result
    result="$(collector_output "certificates" "$artifacts_json" "$count" "$start_ts" "$end_ts")"
    write_collector_result "$output_dir" "certificates" "$result"
}
