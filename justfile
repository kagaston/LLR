# =============================================================================
# IntrusionInspector (Bash Edition) — Task Runner
# =============================================================================
#
# Provides convenient shortcuts for common operations. Requires `just`:
#   macOS:  brew install just
#   Linux:  cargo install just  (or distro package)
#
# Usage:
#   just              — show available recipes
#   just triage       — full pipeline (collect + analyze + report)
#   just collect      — collect artifacts only
#   just verify       — verify evidence integrity
#
# =============================================================================

# Default recipe — show all available commands
default:
    @just --list

# ── Collection & Triage ──────────────────────────────────────────────────────

# Full triage pipeline: collect + analyze + report
triage profile="standard" output="./output":
    sudo bash intrusion-inspector.sh triage -o {{output}} -p {{profile}} -f html,json,csv,console

# Collect artifacts only
collect profile="standard" output="./output":
    sudo bash intrusion-inspector.sh collect -o {{output}} -p {{profile}}

# Analyze previously collected artifacts
analyze input="./output":
    bash intrusion-inspector.sh analyze -i {{input}}

# Analyze with all rule types
analyze-full input="./output":
    bash intrusion-inspector.sh analyze -i {{input}} --iocs rules/iocs/ --sigma rules/sigma/ --yara rules/yara/

# Generate reports from analysis results
report input="./output" format="html":
    bash intrusion-inspector.sh report -i {{input}} -f {{format}}

# Verify evidence integrity against manifest
verify input="./output":
    bash intrusion-inspector.sh verify -i {{input}}

# Full triage with IOC/Sigma/YARA rules
triage-full profile="standard" output="./output":
    sudo bash intrusion-inspector.sh triage -o {{output}} -p {{profile}} \
        --iocs rules/iocs/ --sigma rules/sigma/ --yara rules/yara/ \
        -f html,json,csv,console

# Triage with encrypted evidence package
triage-secure profile="standard" output="./output":
    sudo bash intrusion-inspector.sh triage -o {{output}} -p {{profile}} \
        --secure-output -f html,json,csv,console

# ── Quick Profiles ───────────────────────────────────────────────────────────

# Quick triage (5 collectors, ~30 seconds)
quick output="./output":
    sudo bash intrusion-inspector.sh triage -o {{output}} -p quick -f html,console

# Standard triage (all 16 collectors, ~2 minutes)
standard output="./output":
    sudo bash intrusion-inspector.sh triage -o {{output}} -p standard -f html,json,csv,console

# Full triage with file hashing and YARA (all 16 collectors, ~5 minutes)
full output="./output":
    sudo bash intrusion-inspector.sh triage -o {{output}} -p full \
        --yara rules/yara/ -f html,json,csv,console

# ── Development ──────────────────────────────────────────────────────────────

# Check all bash scripts for syntax errors
lint:
    @echo "Checking bash syntax across all scripts..."
    @find . -name '*.sh' -not -path './output/*' | while read f; do \
        bash -n "$f" 2>&1 && echo "  OK: $f" || echo "  FAIL: $f"; \
    done
    @echo "Done."

# Run shellcheck on all scripts (requires shellcheck)
shellcheck:
    @echo "Running shellcheck..."
    @find . -name '*.sh' -not -path './output/*' -exec shellcheck -x {} +

# Count lines of code across the project
loc:
    @echo "Lines of code (excluding output/):"
    @find . -name '*.sh' -not -path './output/*' | xargs wc -l | tail -1

# List all collector functions
list-collectors:
    @grep -rh '^collect_' lib/collectors/*.sh | sed 's/() {//' | sort

# List all analyzer functions
list-analyzers:
    @grep -rh '^analyze_' lib/analyzers/*.sh | sed 's/() {//' | sort

# List all reporter functions
list-reporters:
    @grep -rh '^report_' lib/reporters/*.sh | sed 's/() {//' | sort

# Show tool version
version:
    @bash intrusion-inspector.sh --version

# ── Cleanup ──────────────────────────────────────────────────────────────────

# Remove output directory
clean:
    rm -rf ./output/

# Remove all generated artifacts
clean-all:
    rm -rf ./output/ ./*.zip
