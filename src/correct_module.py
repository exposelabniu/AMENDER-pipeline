#!/usr/bin/env python3
"""
AMENDER M5 – Metasploit Module Correction Loop
================================================
Invoked when generate_module.py (M4) exits with code 2
(one or both gate checks failed).

Uses the `claude` CLI (Claude Code) as the LLM backend.

Usage:
    python3 correct_module.py <module_path> <gate_errors>
                              [--cve CVE-XXXX-XXXXX]
                              [--msftidy /path/to/msftidy.rb]
                              [--max-iter 20]
                              [--model claude-opus-4-5]

Exit codes:
    0   CONFIRMED  — both gates pass within the iteration budget
    2   EXHAUSTED  — all iterations used, still failing
    3   ENV_ERROR  — environment problem (ruby / msftidy / claude not found)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional import: reuse the project's logger if available on sys.path
# ---------------------------------------------------------------------------
try:
    from logger import write_entry as _log_entry
except ImportError:
    def _log_entry(**kwargs):
        log_dir = Path("logs/training")
        log_dir.mkdir(parents=True, exist_ok=True)
        with open(log_dir / "amender.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(kwargs) + "\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except FileNotFoundError:
        return "missing"


# ---------------------------------------------------------------------------
# Gate runners (mirrors generate_module.py — kept self-contained)
# ---------------------------------------------------------------------------

def _gate_ruby_syntax(rb_path: Path) -> tuple[bool, str]:
    ruby = shutil.which("ruby")
    if not ruby:
        return False, "ruby not found in PATH"
    result = subprocess.run(
        [ruby, "-c", str(rb_path)],
        capture_output=True, text=True, timeout=30
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


def _gate_msftidy(rb_path: Path, msftidy_path: str | None) -> tuple[bool, str]:
    tidy = (
        msftidy_path
        or shutil.which("msftidy.rb")
        or "/usr/share/metasploit-framework/tools/dev/msftidy.rb"
    )
    if not tidy or not Path(tidy).exists():
        return False, f"msftidy.rb not found (tried: {tidy})"

    ruby = shutil.which("ruby")
    if not ruby:
        return False, "ruby not found in PATH"

    result = subprocess.run(
        [ruby, tidy, str(rb_path)],
        capture_output=True, text=True, timeout=30
    )
    output = (result.stdout + result.stderr).strip()
    # Only real [ERROR] lines from msftidy block the gate.
    # git-induced non-zero exit codes and [WARNING] lines are noise.
    has_error = "[ERROR]" in output
    return not has_error, output


def _run_gates(rb_path: Path, msftidy_path: str | None) -> tuple[bool, bool, str, str]:
    """Return (ok1, ok2, out1, out2)."""
    ok1, out1 = _gate_ruby_syntax(rb_path)
    ok2, out2 = _gate_msftidy(rb_path, msftidy_path)
    return ok1, ok2, out1, out2


# ---------------------------------------------------------------------------
# Claude CLI backend
# ---------------------------------------------------------------------------

def _check_claude_cli() -> None:
    if not shutil.which("claude"):
        print(
            "[M5] ERROR: `claude` CLI not found in PATH.\n"
            "       Make sure Claude Code is installed and `claude` is accessible.",
            file=sys.stderr,
        )
        sys.exit(3)


_SYSTEM_PROMPT = textwrap.dedent("""\
    You are AMENDER, an expert Metasploit module developer.
    Your task is to fix a Metasploit Ruby auxiliary module so that it passes
    two automated quality gates:

        χ₁  ruby -c <module.rb>          — Ruby syntax check
        χ₂  msftidy.rb <module.rb>       — Metasploit style/lint (only [ERROR] lines block)

    Rules:
    1. Output ONLY a unified diff (--- a/module.rb +++ b/module.rb format).
       No prose, no markdown code fences, no explanations outside the diff.
    2. The diff must be applicable with: patch -p0 < fix.patch
    3. Make the minimal change that fixes the reported error.
    4. Never change the module's core exploit logic, CVE, references, or
       vulnerability-specific parameters unless they are clearly the bug source.
    5. [WARNING] lines from msftidy do NOT need to be fixed — only [ERROR] lines do.
    6. If you cannot determine a fix, output exactly: CANNOT_FIX
""")


def _build_user_message(rb_source: str, gate_errors: str, iteration: int) -> str:
    return textwrap.dedent(f"""\
        ## Iteration {iteration}

        ### Module source (current version)
        ```ruby
        {rb_source}
        ```

        ### Gate failures
        ```
        {gate_errors[:3000]}
        ```

        Produce the unified diff to fix these gate failures.
    """)


def _query_llm(user_message: str, model: str) -> str:
    full_prompt = f"{_SYSTEM_PROMPT}\n\n---\n\n{user_message}"
    result = subprocess.run(
        ["claude", "--model", model, "-p", full_prompt],
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"`claude` CLI exited with code {result.returncode}. "
            f"stderr: {result.stderr.strip()[:300]}"
        )
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Apply a unified diff
# ---------------------------------------------------------------------------

def _apply_diff(diff_text: str, rb_path: Path) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(diff_text)
        patch_file = fh.name

    try:
        with open(patch_file) as pf:
            result = subprocess.run(
                ["patch", "-p0", str(rb_path)],
                stdin=pf, capture_output=True, text=True, timeout=30,
            )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)
    finally:
        Path(patch_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Main correction loop
# ---------------------------------------------------------------------------

def correction_loop(
    rb_path: Path,
    initial_gate_errors: str,
    *,
    cve: str,
    msftidy_path: str | None,
    model: str,
    max_iter: int,
) -> int:
    _check_claude_cli()

    print(f"[M5] Starting module correction loop — CVE {cve}, max {max_iter} iterations.")
    print(f"[M5] Module: {rb_path}")
    print(f"[M5] Model:  {model}  (via `claude` CLI)")

    current_errors = initial_gate_errors

    for iteration in range(1, max_iter + 1):
        print(f"\n[M5] ── Iteration {iteration}/{max_iter} ──────────────────────────────")
        rb_source = rb_path.read_text(encoding="utf-8", errors="replace")
        sha_before = _sha256(rb_path)

        # ── Ask LLM for a fix ─────────────────────────────────────────────
        print("[M5]  Querying `claude` CLI …")
        try:
            llm_text = _query_llm(
                _build_user_message(rb_source, current_errors, iteration),
                model=model,
            )
        except Exception as exc:
            msg = f"claude CLI error: {exc}"
            print(f"[M5]  ERROR: {msg}", file=sys.stderr)
            _log_entry(
                cve=cve, stage="module_correction", iteration=iteration,
                poc_path=str(rb_path),
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

        print(f"[M5]  LLM response ({len(llm_text)} chars):")
        print(textwrap.indent(llm_text[:600], "        "))

        # ── CANNOT_FIX guard ──────────────────────────────────────────────
        if llm_text.strip() == "CANNOT_FIX":
            diagnosis = "LLM declared CANNOT_FIX — no diff produced."
            print(f"[M5]  {diagnosis}")
            _log_entry(
                cve=cve, stage="module_correction", iteration=iteration,
                poc_path=str(rb_path),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                input_state_sha=sha_before,
                command_run="[claude CLI query]",
                exit_code=2,
                output_snippet=current_errors[:400],
                llm_diagnosis=diagnosis,
                change_made=None,
                result="EXHAUSTED",
            )
            return 2

        # ── Extract diff block if wrapped in fences ────────────────────────
        diff_match = re.search(r"```(?:diff|patch|ruby)?\n(.*?)```", llm_text, re.DOTALL)
        diff_text = diff_match.group(1) if diff_match else llm_text

        # Extract any LLM reasoning text outside the diff block (before/after fences).
        # If the whole response IS the diff (no fences), reasoning is empty.
        reasoning = llm_text if not diff_match else (
            llm_text[:diff_match.start()].strip()
            + ("\n\n" if llm_text[diff_match.end():].strip() else "")
            + llm_text[diff_match.end():].strip()
        ).strip()

        # Build a full diagnosis: LLM reasoning (if any) + the extracted diff.
        # Stored in llm_diagnosis so every log entry records WHY the model
        # made the change, not just WHAT it changed (which goes in change_made).
        llm_diagnosis_full = (
            f"[LLM reasoning]\n{reasoning}\n\n[Extracted diff]\n{diff_text[:600]}"
            if reasoning
            else f"[LLM diff only — no reasoning text]\n{diff_text[:600]}"
        )

        # ── Apply the diff ────────────────────────────────────────────────
        applied, apply_msg = _apply_diff(diff_text, rb_path)
        if not applied:
            diagnosis = f"patch failed to apply: {apply_msg}"
            print(f"[M5]  patch error: {apply_msg}")
            _log_entry(
                cve=cve, stage="module_correction", iteration=iteration,
                poc_path=str(rb_path),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                input_state_sha=sha_before,
                command_run=f"patch -p0 {rb_path}",
                exit_code=2,
                output_snippet=current_errors[:400],
                llm_diagnosis=llm_diagnosis_full[:2000],
                change_made=None,
                result="PATCH_FAIL",
            )
            current_errors = (
                f"Previous diff failed to apply:\n{apply_msg}\n\n"
                f"Original gate errors:\n{initial_gate_errors}"
            )
            continue

        sha_after = _sha256(rb_path)
        print(f"[M5]  Patch applied OK. SHA {sha_before} → {sha_after}")

        # ── Re-run both gates ─────────────────────────────────────────────
        print("[M5]  Re-running gates …")
        ok1, ok2, out1, out2 = _run_gates(rb_path, msftidy_path)
        status1 = "PASS" if ok1 else "FAIL"
        status2 = "PASS" if ok2 else "FAIL"
        print(f"[M5]  χ₁={status1}: {out1[:120]}")
        print(f"[M5]  χ₂={status2}: {out2[:120]}")

        gate_output = f"χ₁ {status1}: {out1}\nχ₂ {status2}: {out2}"
        verdict = "CONFIRMED" if (ok1 and ok2) else "FAIL"

        _log_entry(
            cve=cve, stage="module_correction", iteration=iteration,
            poc_path=str(rb_path),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            input_state_sha=sha_after,
            command_run=f"ruby -c {rb_path} && ruby msftidy.rb {rb_path}",
            exit_code=0 if (ok1 and ok2) else 2,
            output_snippet=gate_output[:400],
            llm_diagnosis=llm_diagnosis_full[:2000],
            change_made=diff_text[:800],
            result=verdict,
        )

        if ok1 and ok2:
            print(f"\n[M5] ✓ CONFIRMED after {iteration} iteration(s). Module fixed.")
            return 0

        current_errors = gate_output
        print("[M5]  Still failing — feeding output to next iteration.")

    print(
        f"\n[M5] EXHAUSTED — {max_iter} iterations used without success.",
        file=sys.stderr,
    )
    return 2


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMENDER M5 – LLM-driven Metasploit module correction loop"
    )
    parser.add_argument("module_path",
                        help="Path to the generated .rb module to fix")
    parser.add_argument("gate_errors", nargs="?", default=None,
                        help="File containing the gate failure output (optional)")
    parser.add_argument("--cve",      default="CVE-UNKNOWN",    help="CVE identifier")
    parser.add_argument("--msftidy",  default=None,             help="Explicit path to msftidy.rb")
    parser.add_argument("--model",    default="claude-opus-4-5", help="Claude model to use")
    parser.add_argument("--max-iter", type=int, default=20,     help="Max correction iterations")
    args = parser.parse_args()

    rb_path = Path(args.module_path).expanduser().resolve()
    if not rb_path.exists():
        print(f"[M5] ERROR: module not found: {rb_path}", file=sys.stderr)
        sys.exit(3)

    if args.gate_errors:
        error_path = Path(args.gate_errors).expanduser().resolve()
        initial_errors = error_path.read_text(encoding="utf-8", errors="replace") \
            if error_path.exists() else "Gate errors not provided."
    else:
        initial_errors = "Gate check failed. No error file provided — re-run gates and fix."

    rc = correction_loop(
        rb_path,
        initial_errors,
        cve=args.cve,
        msftidy_path=args.msftidy,
        model=args.model,
        max_iter=args.max_iter,
    )
    sys.exit(rc)


if __name__ == "__main__":
    main()
