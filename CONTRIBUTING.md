# Contributing to IntrusionInspector (Bash Edition)

## Getting Started

1. Clone the repo
2. Ensure you have bash 3.2+ (macOS default) or 4.0+ (Linux)
3. Run `just lint` to verify all scripts pass syntax checking
4. Run `sudo just quick` to test a quick triage on your machine

## Project Layout

```
intrusion-inspector.sh        # CLI entry point
lib/
├── core/                     # Shared libraries
│   ├── platform.sh           # OS detection, cross-platform wrappers
│   ├── json.sh               # Pure-bash JSON builder
│   ├── logging.sh            # Colored logging + audit trail
│   ├── config.sh             # Constants, defaults, detection lists
│   └── utils.sh              # General utilities
├── collectors/               # 16 forensic artifact collectors
├── analyzers/                # 6 analysis engines
├── reporters/                # 4 report generators
├── evidence/                 # Evidence integrity + chain of custody
└── engine.sh                 # Pipeline orchestrator
profiles/                     # Collection profiles (quick/standard/full)
rules/                        # IOC, Sigma, and YARA detection rules
```

## Development Workflow

```bash
just lint          # Syntax check all scripts
just shellcheck    # Static analysis (requires shellcheck)
just version       # Show version
just quick         # Run quick triage for testing
just clean         # Remove output directory
```

## Adding a Collector

1. Create `lib/collectors/my_collector.sh`
2. Define a function named `collect_my_collector()` that takes `$1` = output_dir
3. Use `write_collector_result` to save output to `raw/my_collector.json`
4. Add `"my_collector"` to the relevant profile arrays in `profiles/*.conf`
5. The engine auto-discovers it via glob sourcing

## Adding an Analyzer

1. Create `lib/analyzers/my_analyzer.sh`
2. Define `analyze_my_analyzer()` that takes `$1` = output_dir
3. Write results to `analysis/my_analyzer.json`
4. Add the analyzer call to `run_analyzers()` in `lib/engine.sh`

## Adding a Reporter

1. Create `lib/reporters/my_format_reporter.sh`
2. Define `report_my_format()` that takes `$1` = output_dir
3. It will be auto-discovered when format "my_format" is requested

## Cross-Platform Guidelines

This tool must run on both macOS and Linux. Key rules:

- **No associative arrays** (`declare -A`) — macOS ships bash 3.2 which doesn't support them
- **No `${var,,}` lowercasing** — use `echo "$var" | tr '[:upper:]' '[:lower:]'`
- Use `has_cmd` to check for command availability before using platform-specific tools
- Use the `compute_sha256`, `file_size`, `epoch_now` wrappers from `utils.sh` and `platform.sh`
- Test on both macOS (BSD userland) and Linux (GNU userland) when possible

## Code Style

- Every file needs a header comment block explaining its purpose
- Every function needs a multi-line comment with parameters and return values
- Use `set -euo pipefail` in entry points
- Use `local` for all function variables
- Quote all variable expansions: `"$var"` not `$var`
- Use `[[ ]]` not `[ ]` for conditionals
- Prefer `printf` over `echo` for formatted output

## Commit Messages

Follow conventional commits:
- `feat: add USB device collector for Linux`
- `fix: handle missing /proc on macOS`
- `perf: use awk for bulk JSON generation in processes collector`
- `docs: add MITRE ATT&CK coverage table to README`
