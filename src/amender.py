#!/usr/bin/env python3
"""
AMENDER – Top-level orchestrator
==================================
Runs the full M1 → M3 pipeline for a single CVE:

    1. (M1) Run the PoC via run_poc.py
    2. (M3) If exit code 2, enter the LLM correction loop
    3. Report final verdict

Usage:
    python3 amender.py --cve CVE-2026-24849 \
        --poc data/pocs/52610.py \
        --target http://localhost:8080 \
        --user admin \
        [--site default] \
        [--probe-file /etc/passwd] \
        [--max-iter 50]

Environment:
    ANTHROPIC_API_KEY   – required for M3 correction loop
                          (prompted interactively if unset)
"""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return time.strftime("%H:%M:%S")


def _banner(label: str) -> None:
    print(f"\n[AMENDER {_ts()}] ── {label} " + "─" * (50 - len(label)))


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    *,
    cve: str,
    poc_path: Path,
    target: str,
    user: str,
    password: str,
    site: str,
    probe_file: str,
    max_iter: int,
    src_dir: Path,
) -> int:
    """
    Execute M1 then M3 if needed.
    Returns the final exit code (0/2/3).
    """
    run_poc_script  = src_dir / "run_poc.py"
    corr_poc_script = src_dir / "correct_poc.py"

    # ── M1: Run the PoC ───────────────────────────────────────────────────
    # Argument names must match run_poc.py's argparse definitions exactly:
    #   --poc, --target, --user, --password, --site, --probe-file
    m1_cmd = [
        sys.executable, str(run_poc_script),
        "--poc",        str(poc_path),
        "--target",     target,
        "--user",       user,
        "--password",   password,
        "--site",       site,
        "--probe-file", probe_file,
    ]

    _banner("M1 – Run PoC")
    # Print command with password redacted
    display_cmd = [a if a != password else "[REDACTED]" for a in m1_cmd]
    print(f"[AMENDER] $ {' '.join(display_cmd)}\n")

    rc = subprocess.run(m1_cmd).returncode

    if rc == 0:
        print(f"\n[AMENDER] ✓ CONFIRMED on first run — no correction needed.")
        return 0

    if rc == 3:
        print(f"\n[AMENDER] ENV_ERROR from M1 — aborting pipeline.", file=sys.stderr)
        return 3

    if rc == 1:
        print(f"\n[AMENDER] Usage/argument error in run_poc.py — check flags.", file=sys.stderr)
        return 1

    # rc == 2 → PoC logic failure, hand off to M3
    print(f"\n[AMENDER] PoC failed (exit 2) — entering M3 correction loop.")

    # Capture the failure output to seed M3's error context
    error_log = Path("logs/training/last_run_error.txt")
    error_log.parent.mkdir(parents=True, exist_ok=True)

    capture = subprocess.run(m1_cmd, capture_output=True, text=True)
    error_log.write_text(
        (capture.stdout + capture.stderr), encoding="utf-8"
    )

    # ── M3: Correction loop ───────────────────────────────────────────────
    m3_cmd = [
        sys.executable, str(corr_poc_script),
        str(poc_path),
        str(error_log),
        "--cve",        cve,
        "--target",     target,
        "--user",       user,
        "--site",       site,
        "--probe-file", probe_file,
        "--max-iter",   str(max_iter),
    ]

    _banner("M3 – Correction Loop")
    display_m3 = [a if a != password else "[REDACTED]" for a in m3_cmd]
    print(f"[AMENDER] $ {' '.join(display_m3)}\n")

    env = os.environ.copy()

    # Pass password via stdin (correct_poc.py calls getpass which reads /dev/tty,
    # so we also export it as an env var and patch the read in correct_poc if needed).
    env["AMENDER_PASSWORD"] = password

    m3_proc = subprocess.run(
        m3_cmd,
        input=password + "\n",   # fed to getpass via stdin
        text=True,                # FIX: tells subprocess input/output are str, not bytes
        env=env,
    )
    rc = m3_proc.returncode

    if rc == 0:
        print(f"\n[AMENDER] ✓ Pipeline COMPLETE — PoC corrected and CONFIRMED.")
    elif rc == 2:
        print(f"\n[AMENDER] EXHAUSTED — correction loop used all {max_iter} iterations.", file=sys.stderr)
    elif rc == 3:
        print(f"\n[AMENDER] ENV_ERROR in M3.", file=sys.stderr)

    return rc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMENDER – agentic PoC correction pipeline"
    )
    parser.add_argument("--cve",        required=True,
                        help="CVE identifier, e.g. CVE-2026-24849")
    parser.add_argument("--poc",        required=True,
                        help="Path to the PoC script (e.g. data/pocs/52610.py)")
    parser.add_argument("--target",     default="http://localhost:8080",
                        help="OpenEMR base URL")
    parser.add_argument("--user",       default="admin",
                        help="OpenEMR username")
    parser.add_argument("--site",       default="default",
                        help="OpenEMR site ID")
    parser.add_argument("--probe-file", default="/etc/passwd",
                        help="File to read as exploit proof")
    parser.add_argument("--max-iter",   type=int, default=50,
                        help="Max M3 correction iterations")
    parser.add_argument("--src-dir",    default="src",
                        help="Directory containing run_poc.py / correct_poc.py")
    args = parser.parse_args()

    password = getpass.getpass(f"[AMENDER] OpenEMR password for '{args.user}': ")

    rc = run_pipeline(
        cve=args.cve,
        poc_path=Path(args.poc).expanduser().resolve(),
        target=args.target,
        user=args.user,
        password=password,
        site=args.site,
        probe_file=args.probe_file,
        max_iter=args.max_iter,
        src_dir=Path(args.src_dir).expanduser().resolve(),
    )
    sys.exit(rc)


if __name__ == "__main__":
    main()
