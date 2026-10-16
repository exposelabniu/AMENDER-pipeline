#!/usr/bin/env python3
"""
AMENDER M3 – PoC Correction Loop
==================================
Invoked when run_poc.py exits with code 2 (PoC logic fail).

Uses the `claude` CLI (Claude Code) as the LLM backend — no separate API
key required; runs on your existing Claude Code subscription.

Usage:
    python3 correct_poc.py <poc_path> <error_log_path> [--cve CVE-XXXX-XXXXX]
                           [--target http://...] [--user admin] [--site default]
                           [--probe-file /etc/passwd] [--max-iter 50]
                           [--model claude-opus-4-5]

Exit codes (mirrors run_poc.py contract):
    0  CONFIRMED   — a corrected PoC reached CONFIRMED within the iteration budget
    2  EXHAUSTED   — all iterations used, still failing
    3  ENV_ERROR   — environment / CLI problem; do not retry automatically
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Optional import: reuse the project's logger if available on sys.path
# ---------------------------------------------------------------------------
try:
    from logger import write_entry as _log_entry          # noqa: F401
except ImportError:
    def _log_entry(**kwargs):                              # type: ignore[misc]
        """Fallback: write directly to the JSONL file."""
        log_dir = Path("logs/training")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "amender.jsonl"
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(kwargs) + "\n")

# ---------------------------------------------------------------------------
# Credential redaction (keep in sync with logger.py)
# ---------------------------------------------------------------------------
_REDACT_PATTERNS = [
    re.compile(r'(?i)(clearPass|password|pass|token|secret|key)\s*[=:]\s*\S+'),
    re.compile(r'(?i)-P\s+\S+'),
    re.compile(r'(?i)--password\s+\S+'),
]


def _redact(text: str) -> str:
    if not text:
        return text
    for pat in _REDACT_PATTERNS:
        text = pat.sub(
            lambda m: m.group(0).split("=")[0].split(":")[0].split()[-1] + "=[REDACTED]",
            text,
        )
    return text


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except FileNotFoundError:
        return "missing"


# ---------------------------------------------------------------------------
# Claude CLI backend
# ---------------------------------------------------------------------------

def _check_claude_cli() -> None:
    """Exit with ENV_ERROR if `claude` is not on PATH."""
    if not shutil.which("claude"):
        print(
            "[M3] ERROR: `claude` CLI not found in PATH.\n"
            "       Make sure Claude Code is installed and `claude` is accessible.\n"
            "       Try: which claude  (or)  claude --version",
            file=sys.stderr,
        )
        sys.exit(3)


def _query_llm(user_message: str, model: str = "claude-opus-4-5") -> str:
    """
    Send a prompt to the `claude` CLI in non-interactive (print) mode.
    The system instructions are prepended to the user message because the
    `claude -p` interface takes a single prompt string.

    Returns the response text.
    Raises RuntimeError on CLI failure.
    """
    full_prompt = f"{_SYSTEM_PROMPT}\n\n---\n\n{user_message}"

    result = subprocess.run(
        ["claude", "--model", model, "-p", full_prompt],
        capture_output=True,
        text=True,
        timeout=180,      # generous; LLM + network latency
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"`claude` CLI exited with code {result.returncode}. "
            f"stderr: {stderr[:300]}"
        )

    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are AMENDER, an expert vulnerability researcher and Python developer.
    Your task is to fix a Python proof-of-concept (PoC) exploit so that it
    successfully demonstrates the vulnerability against the target.

    Rules:
    1. Output ONLY a unified diff (--- a/poc.py +++ b/poc.py format).
       No prose, no markdown code fences, no explanations outside the diff.
    2. The diff must be applicable with: patch -p0 < fix.patch
    3. Make the minimal change that fixes the reported error.
    4. Never remove safety guards, never change the target URL, credentials,
       or file paths unless they are clearly the source of the bug.
    5. If you cannot determine a fix, output exactly: CANNOT_FIX
""")


def _build_user_message(poc_source: str, error_output: str, iteration: int) -> str:
    return textwrap.dedent(f"""\
        ## Iteration {iteration}

        ### PoC source (current version)
        ```python
        {poc_source}
        ```

        ### Error / failure output
        ```
        {error_output[:3000]}
        ```

        Produce the unified diff to fix this PoC.
    """)


# ---------------------------------------------------------------------------
# Apply a unified diff to a file
# ---------------------------------------------------------------------------

def _apply_diff(diff_text: str, poc_path: Path) -> tuple[bool, str]:
    """
    Write diff to a temp file and apply with `patch`.
    Returns (success: bool, message: str).
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(diff_text)
        patch_file = fh.name

    try:
        with open(patch_file, "r") as pf:
            result = subprocess.run(
                ["patch", "-p0", str(poc_path)],
                stdin=pf,
                capture_output=True,
                text=True,
                timeout=30,
            )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, (result.stdout + result.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    finally:
        Path(patch_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Run the PoC and capture exit code + output
# ---------------------------------------------------------------------------

def _run_poc(
    poc_path: Path,
    target: str,
    user: str,
    password: str,
    probe_file: str,
    site: str,
) -> tuple[int, str]:
    """Run the PoC script; return (exit_code, combined_output)."""
    cmd = [
        sys.executable, str(poc_path),
        "-t", target,
        "-u", user,
        "-P", password,
        "-f", probe_file,
        "--site", site,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        combined = (result.stdout + result.stderr).strip()
        return result.returncode, combined
    except subprocess.TimeoutExpired:
        return 3, "PoC timed out after 60 s"
    except Exception as exc:  # noqa: BLE001
        return 3, str(exc)


# ---------------------------------------------------------------------------
# Main correction loop
# ---------------------------------------------------------------------------

def correction_loop(
    poc_path: Path,
    error_log_path: Optional[Path],
    *,
    cve: str,
    target: str,
    user: str,
    password: str,
    probe_file: str,
    site: str,
    model: str = "claude-opus-4-5",
    max_iter: int = 50,
) -> int:
    """
    Drive the LLM correction loop.
    Returns 0 on CONFIRMED, 2 on EXHAUSTED, 3 on ENV_ERROR.
    """
    _check_claude_cli()

    # Seed error from the log file if provided.
    if error_log_path and error_log_path.exists():
        initial_error = error_log_path.read_text(encoding="utf-8", errors="replace")
    else:
        initial_error = "PoC exited with code 2 (logic failure). No error log provided."

    current_error = initial_error

    print(f"[M3] Starting correction loop — CVE {cve}, max {max_iter} iterations.")
    print(f"[M3] PoC:   {poc_path}")
    print(f"[M3] Model: {model}  (via `claude` CLI)")

    for iteration in range(1, max_iter + 1):
        print(f"\n[M3] ── Iteration {iteration}/{max_iter} ──────────────────────────────")
        poc_source = poc_path.read_text(encoding="utf-8", errors="replace")
        sha_before = _sha256(poc_path)

        # ── Ask LLM for a fix ─────────────────────────────────────────────
        print("[M3]  Querying `claude` CLI …")
        try:
            llm_text = _query_llm(
                _build_user_message(poc_source, current_error, iteration),
                model=model,
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"claude CLI error: {exc}"
            print(f"[M3]  ERROR: {msg}", file=sys.stderr)
            _log_entry(
                cve=cve, stage="poc_correction", iteration=iteration,
                poc_path=str(poc_path),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                input_state_sha=sha_before,
                command_run="[claude CLI query]",
                exit_code=3,
                output_snippet=msg[:400],
                llm_diagnosis=msg,
                change_made=None,
                result="ENV_ERROR",
            )
            return 3

        print(f"[M3]  LLM response ({len(llm_text)} chars):")
        print(textwrap.indent(llm_text[:600], "        "))

        # ── CANNOT_FIX guard ──────────────────────────────────────────────
        if llm_text.strip() == "CANNOT_FIX":
            diagnosis = "LLM declared CANNOT_FIX — no diff produced."
            print(f"[M3]  {diagnosis}")
            _log_entry(
                cve=cve, stage="poc_correction", iteration=iteration,
                poc_path=str(poc_path),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                input_state_sha=sha_before,
                command_run="[claude CLI query]",
                exit_code=2,
                output_snippet=_redact(current_error[:400]),
                llm_diagnosis=diagnosis,
                change_made=None,
                result="EXHAUSTED",
            )
            return 2

        # ── Extract diff block if wrapped in fences ────────────────────────
        diff_match = re.search(r"```(?:diff|patch)?\n(.*?)```", llm_text, re.DOTALL)
        diff_text = diff_match.group(1) if diff_match else llm_text

        # Extract any LLM reasoning outside the diff block.
        reasoning = llm_text if not diff_match else (
            llm_text[:diff_match.start()].strip()
            + ("\n\n" if llm_text[diff_match.end():].strip() else "")
            + llm_text[diff_match.end():].strip()
        ).strip()

        # Full diagnosis: LLM reasoning + extracted diff — records WHY as well as WHAT.
        llm_diagnosis_full = (
            f"[LLM reasoning]\n{reasoning}\n\n[Extracted diff]\n{diff_text[:600]}"
            if reasoning
            else f"[LLM diff only — no reasoning text]\n{diff_text[:600]}"
        )

        # ── Apply the diff ────────────────────────────────────────────────
        applied, apply_msg = _apply_diff(diff_text, poc_path)
        if not applied:
            diagnosis = f"patch failed to apply: {apply_msg}"
            print(f"[M3]  patch error: {apply_msg}")
            _log_entry(
                cve=cve, stage="poc_correction", iteration=iteration,
                poc_path=str(poc_path),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                input_state_sha=sha_before,
                command_run=_redact(f"patch -p0 {poc_path}"),
                exit_code=2,
                output_snippet=_redact(current_error[:400]),
                llm_diagnosis=llm_diagnosis_full[:2000],
                change_made=None,
                result="PATCH_FAIL",
            )
            current_error = (
                f"Previous diff failed to apply:\n{apply_msg}\n\n"
                f"Original error:\n{initial_error}"
            )
            continue

        sha_after = _sha256(poc_path)
        print(f"[M3]  Patch applied OK. SHA {sha_before} → {sha_after}")

        # ── Re-run the PoC ────────────────────────────────────────────────
        print("[M3]  Re-running PoC …")
        exit_code, run_output = _run_poc(
            poc_path, target, user, password, probe_file, site
        )
        print(f"[M3]  exit_code={exit_code}")
        print(textwrap.indent(run_output[:400], "        "))

        verdict = (
            "CONFIRMED" if exit_code == 0 else
            "ENV_ERROR" if exit_code == 3 else
            "FAIL"
        )

        _log_entry(
            cve=cve, stage="poc_correction", iteration=iteration,
            poc_path=str(poc_path),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            input_state_sha=sha_after,
            command_run=_redact(
                f"python3 {poc_path} -t {target} -u {user} -P {password} "
                f"-f {probe_file} --site {site}"
            ),
            exit_code=exit_code,
            output_snippet=_redact(run_output[:400]),
            llm_diagnosis=llm_diagnosis_full[:2000],
            change_made=diff_text[:800],
            result=verdict,
        )

        if exit_code == 0:
            print(f"\n[M3] ✓ CONFIRMED after {iteration} iteration(s). PoC fixed.")
            return 0

        if exit_code == 3:
            print("[M3] ENV_ERROR — stopping loop.", file=sys.stderr)
            return 3

        # exit_code == 2 — keep going
        current_error = run_output
        print("[M3]  Still failing — feeding output to next iteration.")

    print(
        f"\n[M3] EXHAUSTED — {max_iter} iterations used without success.",
        file=sys.stderr,
    )
    return 2


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _get_openemr_password(user: str) -> str:
    """Read OpenEMR password from env (set by amender.py) or prompt interactively."""
    return (
        os.environ.get("AMENDER_PASSWORD")
        or getpass.getpass(f"[M3] OpenEMR password for '{user}': ")
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMENDER M3 – LLM-driven PoC correction loop (claude CLI backend)"
    )
    parser.add_argument("poc_path",  help="Path to the PoC Python script to fix")
    parser.add_argument(
        "error_log",
        nargs="?",
        default=None,
        help="Path to file containing the previous run's error output (optional)",
    )
    parser.add_argument("--cve",        default="CVE-UNKNOWN",        help="CVE identifier")
    parser.add_argument("--target",     default="http://localhost:8080", help="OpenEMR base URL")
    parser.add_argument("--user",       default="admin",               help="OpenEMR username")
    parser.add_argument("--site",       default="default",             help="OpenEMR site ID")
    parser.add_argument("--probe-file", default="/etc/passwd",         help="File to read")
    parser.add_argument("--model",      default="claude-opus-4-5",     help="Claude model to use")
    parser.add_argument("--max-iter",   type=int, default=50,          help="Max correction iterations")
    args = parser.parse_args()

    password  = _get_openemr_password(args.user)
    poc_path  = Path(args.poc_path).expanduser().resolve()
    error_log = Path(args.error_log).expanduser().resolve() if args.error_log else None

    if not poc_path.exists():
        print(f"[M3] ERROR: PoC not found: {poc_path}", file=sys.stderr)
        sys.exit(3)

    rc = correction_loop(
        poc_path,
        error_log,
        cve=args.cve,
        target=args.target,
        user=args.user,
        password=password,
        probe_file=args.probe_file,
        site=args.site,
        model=args.model,
        max_iter=args.max_iter,
    )
    sys.exit(rc)


if __name__ == "__main__":
    main()
