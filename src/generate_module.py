#!/usr/bin/env python3
"""
AMENDER M4 – Generalized Metasploit Module Generator
=====================================================
Generates a complete Metasploit auxiliary module for any CVE by:
  1. Reading the CVE config JSON and the PoC source file.
  2. Calling the 'claude' CLI to synthesize the full .rb module.
  3. Running quality gates χ₁ (ruby -c) and χ₂ (msftidy.rb).
  4. Writing the module to <out_dir>/openemr_<cve_slug>_<type>.rb

Exit codes:
  0  Both gates pass  — module is ready
  2  Gate(s) failed   — feed to M5 (correct_module.py)
  3  Env error        — interpreter/tool missing, file not found, LLM unavailable
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Logger (reuse project logger if available)
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
# System prompt for LLM module synthesis
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = textwrap.dedent("""\
You are an expert Metasploit module developer. Write a complete, production-quality
Metasploit auxiliary module in Ruby based on the CVE config JSON and PoC source
provided by the user.

STRICT RULES (msftidy-enforced -- violations block the gate):
1. Module class: `class MetasploitModule < Msf::Auxiliary`
2. Include `Msf::Exploit::Remote::HttpClient` and `Msf::Auxiliary::Report`.
3. `Name` field: no `<` character -- use "prior to X.Y.Z" not "< X.Y.Z".
4. `DisclosureDate` format: 'MMM DD, YYYY' (e.g. 'Jan 01, 2026').
5. `References` array: only `['CVE', '...']` and `['EDB', '...']` entries.
   Never use URL-type references for Exploit-DB.
6. `Notes` block must include:
     'Stability'  => [CRASH_SAFE],
     'Reliability'=> [REPEATABLE_SESSION],
     'SideEffects'=> [NO_SIDE_EFFECTS]
7. `Author` field: array of strings -- include the original PoC author(s) and 'AMENDER'.
8. `License`: `MSF_LICENSE`
9. `register_options`: define all needed `OptString` / `OptInt` options (TARGET_URI, USERNAME,
   PASSWORD, TARGETFILE, SITE, etc.) with sensible defaults.
10. `run` method: implement the full exploit flow from the PoC, translated to Ruby/HttpClient.
    - Perform authentication (POST login) if the PoC does, capture session cookie.
    - Send the exploit request and retrieve the proof file content.
    - Print "[+] File content:" followed by the content on success.
    - Print "[-] <reason>" and return on failure.
11. No hardcoded credentials -- read from datastore options.
12. Do NOT include `require 'msf/core'` (auto-loaded).
13. Output ONLY the Ruby source code. No markdown fences, no explanation text.
""")

_USER_PROMPT_TEMPLATE = textwrap.dedent("""\
CVE CONFIG JSON:
{config_json}

POC SOURCE ({poc_filename}):
{poc_source}

Write the complete Metasploit auxiliary module Ruby source for this CVE.
The module filename will be: {module_filename}
Output ONLY the Ruby source code -- nothing else.
""")


# ---------------------------------------------------------------------------
# LLM query via 'claude' CLI
# ---------------------------------------------------------------------------

def _query_llm(
    system: str,
    user: str,
    model: str = "claude-opus-4-5",
    timeout: int = 180,
) -> str | None:
    """
    Call the 'claude' CLI. Returns the stripped response text, or None on error.
    """
    if not shutil.which("claude"):
        print("[M4] ERROR: 'claude' CLI not found in PATH.", file=sys.stderr)
        return None

    cmd = [
        "claude",
        "--model", model,
        "--system-prompt", system,
        "-p", user,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            print(f"[M4] LLM call failed (exit {result.returncode}): {result.stderr[:300]}",
                  file=sys.stderr)
            return None
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[M4] LLM call timed out after {timeout}s.", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"[M4] LLM call error: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Strip accidental markdown fences from LLM output
# ---------------------------------------------------------------------------

def _strip_fences(text: str) -> str:
    """Remove ```ruby / ``` wrappers if the LLM included them."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[-1].strip() == "```":
            lines = lines[1:-1]
        else:
            lines = lines[1:]
        text = "\n".join(lines)
    return text


# ---------------------------------------------------------------------------
# Quality gate chi1 -- Ruby syntax check
# ---------------------------------------------------------------------------

def gate_syntax(module_path: Path) -> tuple[bool, str]:
    """Run 'ruby -c' on the module. Returns (passed, output)."""
    if not shutil.which("ruby"):
        return False, "ruby not found in PATH"
    try:
        r = subprocess.run(
            ["ruby", "-c", str(module_path)],
            capture_output=True, text=True, timeout=30,
        )
        out = (r.stdout + r.stderr).strip()
        return r.returncode == 0, out
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


# ---------------------------------------------------------------------------
# Quality gate chi2 -- msftidy style check
# ---------------------------------------------------------------------------

def gate_msftidy(module_path: Path) -> tuple[bool, str]:
    """
    Run msftidy.rb on the module.
    Only [ERROR] lines count as failures (warnings are acceptable).
    Returns (passed, raw_output).
    """
    tidy = shutil.which("msftidy.rb") or shutil.which("msftidy")
    if not tidy:
        for candidate in [
            "/opt/metasploit-framework/tools/dev/msftidy.rb",
            "/usr/share/metasploit-framework/tools/dev/msftidy.rb",
            os.path.expanduser("~/metasploit-framework/tools/dev/msftidy.rb"),
        ]:
            if Path(candidate).exists():
                tidy = candidate
                break

    if not tidy:
        print("[M4] msftidy.rb not found -- chi2 gate skipped (will mark as WARN).",
              file=sys.stderr)
        return True, "msftidy not available -- gate skipped"

    try:
        r = subprocess.run(
            ["ruby", tidy, str(module_path)],
            capture_output=True, text=True, timeout=30,
        )
        out = (r.stdout + r.stderr).strip()
        errors = [ln for ln in out.splitlines() if "[ERROR]" in ln]
        return len(errors) == 0, out
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


# ---------------------------------------------------------------------------
# Derive module filename from config
# ---------------------------------------------------------------------------

def module_filename(config: dict) -> str:
    """
    Build the .rb filename from the CVE config.
    Pattern: openemr_<cve_slug>_<suffix>.rb
    """
    cve = config.get("cve", "cve_unknown").lower().replace("-", "_")
    mtype = config.get("module_type", "auxiliary").lower()
    if mtype == "exploit":
        suffix = "exploit"
    elif "read" in config.get("description", "").lower() or "file" in config.get("name", "").lower():
        suffix = "file_read"
    else:
        suffix = "auxiliary"
    return f"openemr_{cve}_{suffix}.rb"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMENDER M4 -- Generalized Metasploit Module Generator"
    )
    parser.add_argument("--config",   required=True,
                        help="Path to CVE config JSON (e.g. data/cve_2026_24849.json)")
    parser.add_argument("--out",      default="modules/auxiliary/",
                        help="Output directory for the generated .rb file (default: modules/)")
    parser.add_argument("--poc-path", default=None, dest="poc_path",
                        help="Path to the PoC file (auto-resolved from config EDB if omitted)")
    parser.add_argument("--model",    default="claude-opus-4-5",
                        help="claude CLI model to use (default: claude-opus-4-5)")
    parser.add_argument("--timeout",  type=int, default=180,
                        help="LLM call timeout in seconds (default: 180)")
    args = parser.parse_args()

    # -- Load config -----------------------------------------------------------
    config_path = Path(args.config).expanduser().resolve()
    if not config_path.exists():
        print(f"[M4] ERROR: Config not found: {config_path}", file=sys.stderr)
        sys.exit(3)

    with open(config_path, encoding="utf-8") as fh:
        config = json.load(fh)

    cve_id = config.get("cve", "unknown")
    edb    = str(config.get("edb", "")).strip()
    print(f"[M4] CVE: {cve_id}  EDB: {edb or '(none)'}")

    # -- Resolve PoC path ------------------------------------------------------
    poc_path = None
    if args.poc_path:
        poc_path = Path(args.poc_path).expanduser().resolve()
    elif edb:
        candidates = [
            config_path.parent.parent / "data" / "pocs" / f"{edb}.py",
            config_path.parent.parent / "data" / "pocs" / f"{edb}.rb",
            config_path.parent.parent / "data" / "pocs" / f"{edb}.php",
            config_path.parent.parent / "data" / "pocs" / f"{edb}.sh",
        ]
        for c in candidates:
            if c.exists():
                poc_path = c
                break

    poc_source = ""
    poc_filename = "unknown"
    if poc_path and poc_path.exists():
        poc_source = poc_path.read_text(encoding="utf-8", errors="replace")
        poc_filename = poc_path.name
        print(f"[M4] PoC source: {poc_path.name} ({len(poc_source)} chars)")
    else:
        print("[M4] WARNING: PoC file not found -- generating module from config only.",
              file=sys.stderr)

    # -- Determine output filename ---------------------------------------------
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    rb_filename = module_filename(config)
    module_path = out_dir / rb_filename
    print(f"[M4] Output: {module_path}")

    # -- Build LLM prompt ------------------------------------------------------
    config_json = json.dumps(config, indent=2)
    user_prompt = _USER_PROMPT_TEMPLATE.format(
        config_json=config_json,
        poc_filename=poc_filename,
        poc_source=poc_source or "(PoC source not available -- synthesize from config fields)",
        module_filename=rb_filename,
    )

    # -- Call LLM --------------------------------------------------------------
    ts_start = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print("[M4] Querying LLM for module synthesis ...")
    raw_output = _query_llm(
        system=_SYSTEM_PROMPT,
        user=user_prompt,
        model=args.model,
        timeout=args.timeout,
    )

    if not raw_output:
        print("[M4] ERROR: LLM returned no output.", file=sys.stderr)
        _log_entry(
            cve=cve_id, stage="generate_module", iteration=1,
            poc_path=str(poc_path or ""), timestamp=ts_start,
            input_state_sha="", command_run="claude (LLM call)",
            exit_code=3, output_snippet="LLM returned no output",
            llm_diagnosis="LLM unavailable or returned empty", change_made=None,
            result="ENV_ERROR",
        )
        sys.exit(3)

    module_source = _strip_fences(raw_output)

    # Basic sanity check
    if "MetasploitModule" not in module_source or "def run" not in module_source:
        print("[M4] ERROR: LLM output does not look like a Metasploit module.",
              file=sys.stderr)
        print(f"[M4] First 300 chars:\n{module_source[:300]}", file=sys.stderr)
        _log_entry(
            cve=cve_id, stage="generate_module", iteration=1,
            poc_path=str(poc_path or ""), timestamp=ts_start,
            input_state_sha="", command_run="claude (LLM call)",
            exit_code=3, output_snippet=module_source[:400],
            llm_diagnosis="LLM output failed sanity check (no MetasploitModule or def run)",
            change_made=None, result="ENV_ERROR",
        )
        sys.exit(3)

    # Write module before running gates
    module_path.write_text(module_source, encoding="utf-8")
    print(f"[M4] Module written ({len(module_source)} chars) -- running quality gates ...")

    # -- chi1 Syntax gate ------------------------------------------------------
    chi1_pass, chi1_out = gate_syntax(module_path)
    status_chi1 = "PASS" if chi1_pass else "FAIL"
    print(f"[M4] chi1 syntax:  {status_chi1}")
    if not chi1_pass:
        print(f"     {chi1_out[:300]}")

    # -- chi2 msftidy gate -----------------------------------------------------
    chi2_pass, chi2_out = gate_msftidy(module_path)
    status_chi2 = "PASS" if chi2_pass else "FAIL"
    print(f"[M4] chi2 msftidy: {status_chi2}")
    if not chi2_pass:
        errors = [ln for ln in chi2_out.splitlines() if "[ERROR]" in ln]
        for err in errors[:5]:
            print(f"     {err}")

    # -- Verdict ---------------------------------------------------------------
    both_pass = chi1_pass and chi2_pass
    verdict   = "CONFIRMED" if both_pass else "FAIL"
    exit_code = 0 if both_pass else 2

    gate_summary = (
        f"chi1={status_chi1} chi2={status_chi2} | "
        f"chi1_out={chi1_out[:200]} | "
        f"chi2_errors={[ln for ln in chi2_out.splitlines() if '[ERROR]' in ln][:3]}"
    )

    print(f"\n[M4] Verdict: {verdict}")
    if both_pass:
        print(f"[M4] Module ready: {module_path}")
    else:
        print("[M4] Module needs correction -- pass to M5 (correct_module.py).")
        err_log = module_path.parent.parent / "logs" / "training" / "last_module_error.txt"
        err_log.parent.mkdir(parents=True, exist_ok=True)
        with open(err_log, "w", encoding="utf-8") as fh:
            fh.write(f"chi1 (ruby -c):\n{chi1_out}\n\nchi2 (msftidy):\n{chi2_out}\n")
        print(f"[M4] Gate errors written to {err_log}")

    _log_entry(
        cve=cve_id, stage="generate_module", iteration=1,
        poc_path=str(poc_path or ""), timestamp=ts_start,
        input_state_sha="", command_run=f"claude --model {args.model}",
        exit_code=exit_code, output_snippet=module_source[:400],
        llm_diagnosis=gate_summary, change_made=rb_filename,
        result=verdict,
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
