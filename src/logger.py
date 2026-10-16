#!/usr/bin/env python3
"""
AMENDER M2 – JSONL Training Logger
====================================
Central logger for all AMENDER pipeline stages.
Writes one JSON line per event to logs/training/amender.jsonl.
Credentials are redacted before any write.
"""

import hashlib
import json
import re
import time
from pathlib import Path

LOG_DIR  = Path("logs/training")
LOG_FILE = LOG_DIR / "amender.jsonl"

_REDACT_PATTERNS = [
    re.compile(r'(?i)(clearPass|password|pass|token|secret|key)\s*[=:]\s*\S+'),
    re.compile(r'(?i)-P\s+\S+'),
    re.compile(r'(?i)--password\s+\S+'),
]


def redact(text: str) -> str:
    if not text:
        return text
    for pat in _REDACT_PATTERNS:
        text = pat.sub(
            lambda m: m.group(0).split("=")[0].split(":")[0].split()[-1] + "=[REDACTED]",
            text,
        )
    return text


def sha256_file(path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    except FileNotFoundError:
        return "missing"


def write_entry(
    *,
    cve: str,
    stage: str,
    iteration: int,
    poc_path: str,
    command_run: str,
    exit_code: int,
    output_snippet: str,
    result: str,
    llm_diagnosis=None,
    change_made=None,
    # Optional overrides — callers may pre-compute these; if omitted, generated here.
    timestamp: str = None,
    input_state_sha: str = None,
) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "cve":            cve,
        "stage":          stage,
        "iteration":      iteration,
        "timestamp":      timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_state_sha": input_state_sha or sha256_file(poc_path),
        "command_run":    redact(command_run),
        "exit_code":      exit_code,
        "output_snippet": redact(str(output_snippet)[:400]),
        "llm_diagnosis":  llm_diagnosis,
        "change_made":    change_made,
        "result":         result,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
