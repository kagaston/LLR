#!/usr/bin/env bash
# =============================================================================
# lib/evidence/chain_of_custody.sh — Case Metadata & Chain of Custody
# =============================================================================
#
# Maintains a chain_of_custody.json file that records who collected the
# evidence, when, where, and with what tool. This is a standard DFIR
# requirement for establishing evidence provenance and admissibility.
#
# Architecture role:
#   Part of the evidence subsystem (alongside integrity.sh). Called by
#   engine_collect() and engine_triage() at the start and end of collection
#   to bracket the evidence-gathering window with timestamps.
#
# Lifecycle:
#   1. init_chain_of_custody()     — Called BEFORE any collectors run.
#      Creates chain_of_custody.json with case metadata, platform info,
#      and the collection_start timestamp. collection_end is initially empty.
#
#   2. finalize_chain_of_custody() — Called AFTER all collectors finish.
#      Updates collection_end with the current timestamp to record when
#      evidence gathering concluded.
#
# File contents (chain_of_custody.json):
#   {
#     "case_id": "...",           — Investigator-assigned case identifier
#     "examiner": "...",          — Name of the person running the tool
#     "hostname": "...",          — Endpoint hostname at collection time
#     "platform": "...",          — OS type (darwin/linux)
#     "os_version": "...",        — Kernel version from uname -r
#     "tool_version": "...",      — IntrusionInspector version
#     "collection_start": "...",  — UTC timestamp when collection began
#     "collection_end": "...",    — UTC timestamp when collection finished
#     "output_directory": "..."   — Absolute path to the output directory
#   }
#
# =============================================================================

# Module-level variable tracking the chain of custody file path.
# Set by init_chain_of_custody and reused by finalize_chain_of_custody.
_COC_FILE=""

# These globals are set by generate_manifest() in integrity.sh so that
# finalize_chain_of_custody can embed them in the final COC record.
MANIFEST_SHA256="${MANIFEST_SHA256:-}"
MANIFEST_FILE_COUNT="${MANIFEST_FILE_COUNT:-0}"

# -----------------------------------------------------------------------------
# init_chain_of_custody — Create the chain of custody record
#
# Parameters:
#   $1  output_dir — Root output directory for this collection run
#   $2  case_id    — Case identifier (from --case-id flag or config default)
#   $3  examiner   — Examiner name (from --examiner flag or config default)
#
# Captures the collection start timestamp and all environmental context
# (hostname, platform, OS version) at the moment collection begins.
# The collection_end field is left empty — finalize fills it in later.
# -----------------------------------------------------------------------------
init_chain_of_custody() {
    local output_dir="$1"
    local case_id="$2"
    local examiner="$3"

    _COC_FILE="${output_dir}/chain_of_custody.json"

    # Build the initial custody record with empty collection_end
    local coc
    coc="$(json_object \
        "$(json_kvs "case_id" "$case_id")" \
        "$(json_kvs "examiner" "$examiner")" \
        "$(json_kvs "hostname" "$(hostname)")" \
        "$(json_kvs "platform" "$PLATFORM_LOWER")" \
        "$(json_kvs "os_version" "$(uname -r)")" \
        "$(json_kvs "tool_version" "$VERSION")" \
        "$(json_kvs "collection_start" "$(utc_now)")" \
        "$(json_kvs "collection_end" "")" \
        "$(json_kvs "output_directory" "$output_dir")"
    )"

    json_write "$_COC_FILE" "$coc"
    audit_log "chain_of_custody" "Initialized: case=${case_id} examiner=${examiner}"
}

# -----------------------------------------------------------------------------
# finalize_chain_of_custody — Stamp end time, embed manifest hash and counts
#
# Parameters:
#   $1  output_dir      — Root output directory (used to locate the file if
#                          _COC_FILE wasn't set, e.g., in standalone analyze runs)
#   $2  total_artifacts  — (optional) Total artifact count across all collectors
#
# Updates the chain_of_custody.json with:
#   - collection_end     — UTC timestamp when collection finished
#   - manifest_sha256    — SHA-256 hash of the manifest.json file itself
#   - total_artifacts    — Sum of artifacts across all collectors
#   - total_files        — Number of evidence files recorded in the manifest
#
# Uses jq for clean JSON mutation when available; falls back to rebuilding
# the JSON from scratch when jq is not installed.
# -----------------------------------------------------------------------------
finalize_chain_of_custody() {
    local output_dir="$1"
    local total_artifacts="${2:-0}"

    [[ -z "$_COC_FILE" ]] && _COC_FILE="${output_dir}/chain_of_custody.json"
    [[ -f "$_COC_FILE" ]] || return 0

    local end_ts
    end_ts="$(utc_now)"

    local content
    content="$(cat "$_COC_FILE")"

    if has_cmd jq; then
        echo "$content" | jq \
            --arg ts "$end_ts" \
            --arg mhash "${MANIFEST_SHA256:-}" \
            --argjson ta "${total_artifacts:-0}" \
            --argjson tf "${MANIFEST_FILE_COUNT:-0}" \
            '.collection_end = $ts | .manifest_sha256 = $mhash | .total_artifacts = $ta | .total_files = $tf' \
            > "$_COC_FILE" 2>/dev/null
    else
        # Patch collection_end via string replacement
        content="${content/\"collection_end\": \"\"/\"collection_end\": \"${end_ts}\"}"

        # Inject new fields before the closing brace. This is safe because
        # init_chain_of_custody writes well-formed JSON with a final "}" on its own line.
        local extra=""
        extra+="\"manifest_sha256\": \"${MANIFEST_SHA256:-}\","
        extra+="\"total_artifacts\": ${total_artifacts:-0},"
        extra+="\"total_files\": ${MANIFEST_FILE_COUNT:-0}"

        # Replace the last "}" with extra fields + "}"
        content="${content%\}*}${extra}}"
        printf '%s\n' "$content" > "$_COC_FILE"
    fi

    audit_log "chain_of_custody" "Finalized: manifest_sha256=${MANIFEST_SHA256:-none}, artifacts=${total_artifacts}, files=${MANIFEST_FILE_COUNT:-0}"
}
