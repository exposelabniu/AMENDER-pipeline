# AMENDER: Automated Metasploit Module ENgineering and Diagnostic Exploit Runner

A semi-automated pipeline for CVE verification and Metasploit module synthesis, built as part of PhD research in vulnerability automation at Northern Illinois University.

## What This Does

AMENDER takes a CVE ID and an Exploit-DB reference, then runs a 7-stage agentic pipeline to:

1. **M1** — Run a PoC exploit against a local lab target and confirm the vulnerability is live
2. **M3** — If the PoC fails, diagnose and repair it automatically (up to N iterations)
3. **M4** — Synthesize a Metasploit auxiliary/exploit module from the confirmed PoC
4. **M5** — Validate and correct the generated module (syntax, msftidy, live test)
5. **M7** — Update the dashboard with results

All pipeline runs are logged to `logs/training/amender.jsonl` for reproducibility and analysis.

## CVEs Covered

| CVE | Class | Target | Status |
|-----|-------|--------|--------|
| CVE-2018-15142 | File Read | OpenEMR 5.0.1.3 (port 8082) | CONFIRMED |
| CVE-2018-15139 | RCE / Upload | OpenEMR 5.0.1.3 (port 8082) | CONFIRMED |
| CVE-2026-24849 | File Read | OpenEMR 7.0.2 (port 8080) | CONFIRMED |
| CVE-2018-15149 | SQL Injection | OpenEMR 5.0.1.3 (port 8082) | In Progress |

## Repository Layout

```
openemr-amender/
├── src/                        # Pipeline source code
│   ├── run_poc.py              # M1: language-agnostic PoC runner
│   ├── correct_poc.py          # M3: LLM-driven PoC correction loop
│   ├── generate_module.py      # M4: Metasploit module synthesis
│   ├── correct_module.py       # M5: module validation and correction
│   ├── dashboard.py            # M7: HTML dashboard generator
│   ├── fetch_poc.py            # EDB PoC downloader
│   ├── logger.py               # Shared JSONL logger
│   └── amender.py              # Pipeline orchestrator
│
├── data/
│   ├── *.json                  # CVE config files (one per CVE)
│   ├── pocs/                   # Synthesized / adapted PoC scripts
│   └── cve/                    # Research notes and access matrices
│
├── modules/
│   └── auxiliary/admin/http/   # Generated Metasploit modules
│       ├── openemr_cve_2018_15139_exploit.rb
│       ├── openemr_cve_2018_15142_file_read.rb
│       ├── openemr_cve_2018_15149_sqli.rb
│       └── openemr_cve_2026_24849_file_read.rb
│
├── docker/
│   └── docker-compose.yml      # Lab environment (OpenEMR 5.0.1.3 + 7.0.2)
│
├── logs/
│   ├── training/amender.jsonl  # Full pipeline run log (all CVEs, all stages)
│   └── dashboard.html          # Auto-generated visual dashboard
│
├── results/
│   └── evaluation/             # Evaluation summaries
│
└── .claude/commands/amender.md # Claude Code /amender slash command definition
```

## Reproducing the Lab

### Prerequisites

- Docker and Docker Compose
- Python 3.10+
- Metasploit Framework (`msfconsole`, `msftidy`)
- Claude CLI (`claude`) with API access

### 1. Start the OpenEMR lab

```bash
cd docker
docker compose up -d
# OpenEMR 7.0.2  → http://localhost:8080  (admin / admin)
# OpenEMR 5.0.1.3 → http://localhost:8082  (admin / admin)
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the pipeline against a CVE

Using the Claude Code `/amender` slash command (from inside the project directory):

```
/amender CVE-2018-15142 --target http://localhost:8082 --user admin --password admin
```

Or run stages manually:

```bash
# M1: Run the PoC
python3 src/run_poc.py \
  --poc data/pocs/45202.py \
  --cve CVE-2018-15142 \
  --target http://localhost:8082 \
  --user admin --password admin

# M7: Regenerate the dashboard
python3 src/dashboard.py
# Open logs/dashboard.html in a browser
```

### 4. View results

Open `logs/dashboard.html` in any browser. It reads from `logs/training/amender.jsonl` and shows one collapsible card per CVE with full iteration history.

## Security Note

This repository targets a **local Docker lab only**. The pipeline enforces this:

- Targets must be `localhost`, `127.0.0.1`, or an RFC-1918 address
- Synthesized PoCs implement read/confirm paths only — no write, delete, or code-execution payloads
- Credentials never written to files; passed via `AMENDER_PASSWORD` env var or `--password` flag

## Research Context

This project is part of ongoing PhD research on semi-automated vulnerability verification pipelines at NIU. The JSONL log (`logs/training/amender.jsonl`) captures per-stage inputs, outputs, LLM diagnoses, and corrections — intended as a training dataset for future work on automated exploit module generation.
