# AMENDER: AI-Assisted Metasploit Exploit Module Synthesis via Disclosure-Aware Extraction and Analyst-in-the-Loop Review for OpenEMR

## About

This repository contains the implementation and experimental artifacts for AMENDER, a pipeline that automates the synthesis of functional Metasploit exploit modules from publicly available vulnerability disclosures.

AMENDER targets two real-world vulnerabilities in OpenEMR, a widely deployed open-source electronic health records system: CVE-2026-24849 (CVSS 9.9, arbitrary file read/write via a fax document disposal endpoint) and CVE-2026-33305 (CVSS 5.4, authorization bypass via credential injection in the setup controller). Starting from CVE/NVD advisories, patch diffs, and source code, the pipeline uses a large language model (LLM) to iteratively draft, critique, and refine Ruby exploit modules across four structured phases and 13 analyst-guided synthesis steps. Each candidate module is validated through three conformance gates: Ruby syntax check, msftidy style compliance, and live functional testing against a Dockerized OpenEMR instance.

The repository includes the synthesized Metasploit modules, Python proof-of-concept scripts, the Docker-based lab environment, and evaluation logs from all 13 pipeline iterations. This work is submitted to ICCFN 2026 and is currently under blind review.

Companion paper: "AMENDER: AI-Assisted Metasploit Exploit Module Synthesis via Disclosure-Aware Extraction and Analyst-in-the-Loop Review for OpenEMR" (submitted to ICCFN 2026, under blind review)

## Repository Structure

```
AMENDER-2026/
|-- data/
| +-- cve/
| |-- research_log_session2.md
| +-- cve_2026_24849_access_matrix.md
|-- docker/
| +-- docker-compose.yml
|-- logs/
| |-- llm/
| | |-- cve_2026_24849_faxsms_file_read.rb
| | |-- cve_2026_24849_rcfax_dispose.rb
| | |-- cve_2026_33305_save_setup.rb
| | |-- cve_2026_24849_file_read.py
| | |-- cve_2026_24849_original_poc.py
| | +-- cve_2026_33305_save_setup.py
| +-- conformance/
|-- results/
| +-- evaluation/
| +-- evaluation_summary.md
+-- src/
|-- modules/
| |-- cve_2026_24849_faxsms_file_read.rb
| |-- cve_2026_24849_rcfax_dispose.rb
| +-- cve_2026_33305_save_setup.rb
|-- poc/
| |-- cve_2026_24849_original_poc.py
| |-- cve_2026_24849_file_read.py
| +-- cve_2026_33305_save_setup.py
|-- openemr_cve_analysis.py <- NVD API script; produces Fig. 1
+-- README.md <- usage for openemr_cve_analysis.py
```

## CVE Enumeration Script (Figure 1)

`src/openemr_cve_analysis.py` queries the NVD REST API v2.0 to enumerate all OpenEMR CVEs, computes annual CVSS statistics, and cross-references existing Metasploit coverage. The bar chart in Figure 1 of the companion paper was generated using this script.

See [`src/README.md`](src/README.md) for usage instructions and output format.

## Vulnerabilities Covered

| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2026-24849 | 9.9 Critical | Arbitrary file read/write via `disposeDocument()` in EtherFaxActions |
| CVE-2026-33305 | 5.4 Medium | Authorization bypass; AppDispatch dispatches actions before ACL checks |

## Prerequisites

- Docker and Docker Compose
- Metasploit Framework (msfconsole)
- Python 3 with requests library

## Step 1 - Start the Lab Environment

```bash
cd docker/
docker-compose up -d
```

This starts OpenEMR 7.0.2 on http://localhost:8080. Default credentials: admin / pass. Wait ~30 seconds before running any modules.

## Step 2 - Copy Metasploit Modules

```bash
cp src/modules/cve_2026_24849_faxsms_file_read.rb ~/.msf4/modules/auxiliary/gather/
cp src/modules/cve_2026_24849_rcfax_dispose.rb     ~/.msf4/modules/auxiliary/gather/
cp src/modules/cve_2026_33305_save_setup.rb        ~/.msf4/modules/auxiliary/gather/
```

## Step 3 - Run CVE-2026-24849 Module (File Read)

```bash
msfconsole -q
msf > reload_all
msf > use auxiliary/gather/cve_2026_24849_faxsms_file_read
msf > set RHOSTS 127.0.0.1
msf > set RPORT 8300
msf > set USERNAME admin
msf > set PASSWORD pass
msf > set TARGETFILE /etc/passwd
msf > run
```

Expected: contents of /etc/passwd returned in module output.

## Step 4 - Run CVE-2026-33305 Module (Credential Injection)

```bash
msf > use auxiliary/gather/cve_2026_33305_save_setup
msf > set RHOSTS 127.0.0.1
msf > set RPORT 8300
msf > set USERNAME admin
msf > set PASSWORD pass
msf > run
```

Expected: vendor credentials overwritten; module confirms write success.

## Step 5 - Verify with Python PoC (optional)

```bash
python3 src/poc/cve_2026_24849_file_read.py
```

## Stopping the Lab

```bash
docker-compose down
```

## Notes

- All modules were synthesised by the AMENDER pipeline and validated against the lab environment described in the paper (Section 4).
- Conformance gates passed: X1 Ruby syntax, X2 msftidy, X3 live functional.
- Author identity withheld for blind review.
