# IntrusionInspector (Bash Edition)

Cross-platform DFIR (Digital Forensics and Incident Response) triage tool for
corporate endpoints, written entirely in bash. Collects forensic artifacts,
analyzes them for indicators of compromise, and produces structured reports with
MITRE ATT&CK mapping.

**Supported Platforms:** macOS, Linux (Debian/Ubuntu, RHEL/CentOS/Fedora)

## Quick Start

```bash
# Full triage (requires root)
sudo ./intrusion-inspector.sh triage -o ./case_001 -p standard \
    --case-id CASE001 --examiner "Jane Doe" -f html,json,csv,console

# Quick collection only
sudo ./intrusion-inspector.sh collect -o ./case_001 -p quick

# Analyze existing collection with IOC rules
sudo ./intrusion-inspector.sh analyze -i ./case_001 --iocs rules/iocs/

# Generate a report from previous analysis
./intrusion-inspector.sh report -i ./case_001 -f html

# Verify evidence integrity
./intrusion-inspector.sh verify -i ./case_001
```

## Commands

| Command   | Description                                         |
|-----------|-----------------------------------------------------|
| `triage`  | Full pipeline: collect, analyze, report             |
| `collect` | Collect forensic artifacts from the endpoint        |
| `analyze` | Analyze previously collected artifacts              |
| `report`  | Generate reports from analysis results              |
| `verify`  | Verify evidence integrity against SHA-256 manifest  |

## Collection Profiles

| Profile    | Collectors | Hash Files | YARA  | Timeout |
|------------|-----------|------------|-------|---------|
| `quick`    | 5         | No         | No    | 60s     |
| `standard` | 16        | No         | No    | 300s    |
| `full`     | 16        | Yes        | Yes   | 600s    |

## Collectors (16)

| Collector           | Description                                    |
|---------------------|------------------------------------------------|
| `system_info`       | Hostname, OS, CPU, RAM, network interfaces     |
| `processes`         | Running process enumeration                    |
| `network`           | Connections, DNS config, ARP table             |
| `users`             | User accounts, login history, active sessions  |
| `persistence`       | Cron, systemd, launchd, login items            |
| `filesystem`        | Temp directory scan, file metadata             |
| `logs`              | System logs, auth logs, journal                |
| `browser`           | Chrome, Firefox, Safari history (via sqlite3)  |
| `shell_history`     | Bash, zsh, fish command history                |
| `usb_devices`       | USB device history                             |
| `installed_software`| dpkg, rpm, snap, brew, system_profiler         |
| `kernel_modules`    | Loaded kernel modules/extensions               |
| `firewall`          | iptables, nftables, ufw, pfctl rules           |
| `environment`       | Environment variables (flags suspicious ones)  |
| `clipboard`         | Clipboard contents with IOC detection          |
| `certificates`      | System certificate stores                      |

## Analyzers (6)

| Analyzer            | Description                                    |
|---------------------|------------------------------------------------|
| IOC Scanner         | Match artifacts against YAML IOC rules         |
| Anomaly Detector    | 12 heuristic checks with MITRE mapping         |
| Timeline            | Aggregate and sort timestamps                  |
| Sigma Scanner       | Basic Sigma rule matching                      |
| YARA Scanner        | Pattern matching via `yara` CLI (optional)     |
| MITRE Mapper        | ATT&CK technique aggregation and risk scoring  |

## Report Formats

- **HTML** — Self-contained dark-theme report with risk score, findings table,
  MITRE summary, and collector overview
- **JSON** — Full structured export with ATT&CK Navigator layer
- **CSV** — Timeline and findings spreadsheets
- **Console** — ANSI-colored terminal output

## Output Layout

```
output/
├── raw/                          # One JSON per collector
├── analysis/                     # Analysis results
│   ├── anomaly_detector.json
│   ├── timeline.json
│   ├── ioc_scanner.json
│   └── mitre_attack_summary.json
├── report.html
├── report.json
├── timeline.csv
├── findings.csv
├── attack_navigator_layer.json
├── manifest.json                 # SHA-256 evidence manifest
├── audit.log                     # Timestamped audit log
└── chain_of_custody.json         # Case metadata
```

## Evidence Integrity

Every file produced during collection is SHA-256 hashed into `manifest.json`.
Use the `verify` command to check that no files have been tampered with since
collection.

## Dependencies

**Required:** bash 4+, coreutils, awk, grep, sed, find

**Optional (enhanced functionality):**
- `jq` — Pretty-printed JSON output
- `sqlite3` — Browser history collection
- `yara` — YARA rule scanning
- `zip` — Encrypted evidence packages

## Environment Variables

| Variable        | Default    | Description                   |
|-----------------|------------|-------------------------------|
| `II_OUTPUT_DIR` | `./output` | Default output directory      |
| `II_CASE_ID`    | (empty)    | Default case identifier       |
| `II_EXAMINER`   | (empty)    | Default examiner name         |
| `LOG_LEVEL`     | `INFO`     | Log level: DEBUG/INFO/WARN/ERROR |

## Project Structure

```
intrusion-inspector.sh        # CLI entry point
lib/
  core/                       # Platform detection, JSON, logging, config
  collectors/                 # 16 forensic artifact collectors
  analyzers/                  # 6 analysis engines
  reporters/                  # 4 report generators
  evidence/                   # Integrity and chain of custody
profiles/                     # Collection profiles (quick/standard/full)
rules/                        # Detection rules (IOC, Sigma, YARA)
```

## License

MIT
