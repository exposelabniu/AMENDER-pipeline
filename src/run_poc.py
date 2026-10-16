#!/usr/bin/env python3
"""
AMENDER M1 – Language-Agnostic PoC Runner (Generalized)
========================================================
Auto-detects the PoC language (Python / Ruby / PHP / Bash),
maps the PoC's argument flags to the canonical AMENDER interface,
handles interactive input() prompts via stdin piping, then
confirms success by looking for probe-file content in the output.

Canonical interface (caller always uses this):
  --poc        path to PoC file
  --target     full base URL  (e.g. http://192.168.1.50:8080)
  --user       username        (default: admin)
  --password   password        (or AMENDER_PASSWORD env var)
  --site       site ID         (default: default)
  --probe-file remote file to read as proof  (default: /etc/passwd)

Exit codes:
  0  CONFIRMED  — probe-file content or explicit success signal found
  1  Arg error  — bad invocation of this script itself
  2  Logic fail — exploit ran but did not produce confirmation
  3  Env error  — interpreter missing, PoC not found, timeout, etc.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

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
# Credential redaction
# ---------------------------------------------------------------------------
_REDACT_RE = [
    re.compile(r'(?i)(clearPass|password|pass|token|secret|key)\s*[=:]\s*\S+'),
    re.compile(r'(?i)-[pP]\s+\S+'),
    re.compile(r'(?i)--password\s+\S+'),
]


def _redact(text: str) -> str:
    for pat in _REDACT_RE:
        text = pat.sub(
            lambda m: m.group(0).split("=")[0].split(":")[0].split()[-1] + "=[REDACTED]",
            text,
        )
    return text


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
_SHEBANG_RE = re.compile(r"^#!.*?(python|ruby|php|bash|sh)\b", re.I)
_IMPORT_RE  = re.compile(r"^\s*(import|from)\s+\w", re.M)


def detect_interpreter(poc_path: Path) -> tuple[str, str]:
    """
    Return (interpreter_binary, detection_reason).
    Priority: shebang → extension → content heuristic → default python3.
    """
    try:
        head = poc_path.read_text(encoding="utf-8", errors="replace")[:512]
    except OSError:
        return "python3", "default (unreadable)"

    first_line = head.split("\n")[0]
    m = _SHEBANG_RE.match(first_line)
    if m:
        lang = m.group(1).lower()
        interp = {"python": "python3", "ruby": "ruby", "php": "php",
                  "bash": "bash", "sh": "bash"}.get(lang, "python3")
        return interp, f"shebang ({first_line.strip()})"

    ext = poc_path.suffix.lower()
    ext_map = {".py": "python3", ".rb": "ruby", ".php": "php",
               ".sh": "bash", ".bash": "bash"}
    if ext in ext_map:
        return ext_map[ext], f"extension ({ext})"

    # Content heuristic
    if _IMPORT_RE.search(head):
        return "python3", "content heuristic (import statement)"
    if "require " in head or "def " in head or "end\n" in head:
        return "ruby", "content heuristic (Ruby keywords)"
    if "<?php" in head:
        return "php", "content heuristic (<?php)"

    return "python3", "default fallback"


# ---------------------------------------------------------------------------
# Flag parsing — detect the PoC's own argparse / optparse / OptionParser defs
# ---------------------------------------------------------------------------

# Roles we care about, with keyword lists ordered by specificity
_ROLE_KEYWORDS: dict[str, list[str]] = {
    "host":     ["ip", "host", "target", "url", "server", "addr", "address", "rhost"],
    "port":     ["port"],
    "path":     ["path", "uri", "base", "install", "root", "webroot"],
    "user":     ["user", "username", "login", "uname"],
    "password": ["pass", "password", "passwd", "secret", "cred", "clearpass"],
    "probe":    ["file", "filepath", "filename", "probe", "download", "read", "lfile"],
    "site":     ["site"],
}

# Extract quoted strings from a single argument definition block
_QUOTED_RE = re.compile(r"['\"]([^'\"]{1,80})['\"]")
# Python: add_argument(...)  Ruby: opts.on(...)
_ARGDEF_RE = re.compile(
    r"(?:add_argument|opts?\.on|parser\.add|op\.on)\s*\(([^)]{0,400})\)",
    re.S,
)


def _classify_role(flag_strings: list[str], help_strings: list[str]) -> str | None:
    combined = " ".join(flag_strings + help_strings).lower()
    # password must come before 'pass' (substring) so check longest first
    for role in ["password", "host", "port", "path", "user", "probe", "site"]:
        if any(k in combined for k in _ROLE_KEYWORDS[role]):
            return role
    return None


def parse_poc_flags(source: str) -> dict[str, list[str]]:
    """
    Return a dict mapping role → [best_flag, ...] found in the PoC source.
    Example: {'host': ['--IP', '-T'], 'port': ['--PORT', '-P'], ...}
    """
    roles: dict[str, list[str]] = {}
    seen_flags: set[str] = set()

    for m in _ARGDEF_RE.finditer(source):
        block = m.group(1)
        strings = _QUOTED_RE.findall(block)
        flags   = [s for s in strings if s.startswith("-")]
        others  = [s for s in strings if not s.startswith("-")]
        if not flags:
            continue
        role = _classify_role(flags, others)
        if role and not any(f in seen_flags for f in flags):
            roles.setdefault(role, []).extend(flags)
            seen_flags.update(flags)

    return roles


def _best_flag(flag_list: list[str]) -> str:
    """Prefer --long over -short."""
    long_flags = [f for f in flag_list if f.startswith("--")]
    return long_flags[0] if long_flags else flag_list[0]


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------

def build_command(
    interpreter: str,
    poc_path: Path,
    source: str,
    target: str,
    user: str,
    password: str,
    probe_file: str,
    site: str,
) -> tuple[list[str], str | None]:
    """
    Return (cmd_list, stdin_text_or_None).

    Strategy:
      1. Parse the PoC's flag definitions.
      2. Map each canonical param (host, port, path, user, password,
         probe, site) to the PoC's flag.
      3. Collect interactive input() prompts and pipe answers via stdin.
      4. If no flags found at all, try the AMENDER canonical flags directly.
    """
    parsed = urlparse(target)
    host   = parsed.hostname or "localhost"
    port   = str(parsed.port or (443 if parsed.scheme == "https" else 80))
    path   = parsed.path.rstrip("/") or "/"

    poc_flags = parse_poc_flags(source)

    cmd: list[str] = [interpreter, str(poc_path)]
    stdin_lines: list[str] = []

    # ── Map flags ────────────────────────────────────────────────────────────
    role_values = {
        "host":     host,
        "port":     port,
        "path":     path,
        "user":     user,
        "password": password,
        "probe":    probe_file,
        "site":     site,
    }

    # Fast path: if the PoC already exposes AMENDER's canonical interface,
    # use it verbatim with the FULL target URL. The fuzzy role mapper below is
    # a fallback for foreign PoCs only; it mis-handles PoCs whose own --target
    # takes a full base URL and whose --file/--output help text trips the
    # keyword heuristic (e.g. help "absolute path ..." misclassified as path).
    # Accept either --file or --probe-file for probe file argument.
    canonical_base = ["--target", "--user", "--password", "--site"]
    canonical_probe = "--probe-file" if "--probe-file" in source else "--file"
    if all(flag in source for flag in canonical_base) and canonical_probe in source:
        cmd.extend(["--target", target])
        cmd.extend(["--user", user])
        cmd.extend(["--password", password])
        cmd.extend(["--site", site])
        cmd.extend([canonical_probe, probe_file])
    elif poc_flags:
        for role, value in role_values.items():
            flags = poc_flags.get(role)
            if flags:
                cmd.extend([_best_flag(flags), value])
    else:
        # No flag definitions found — try canonical AMENDER flags as a fallback
        # (works for PoCs already written with our interface)
        print("[M1]  No argparse definitions found — trying canonical flags.",
              file=sys.stderr)
        cmd += ["-t", target, "-u", user, "-P", password,
                "-f", probe_file, "--site", site]

    # ── Handle interactive input() calls ─────────────────────────────────────
    for prompt_text in re.findall(r"input\s*\(\s*['\"]([^'\"]*)['\"]", source):
        pt = prompt_text.lower()
        if any(k in pt for k in ["file", "path", "filepath"]):
            stdin_lines.append(probe_file)
        elif any(k in pt for k in ["host", "ip", "target", "server"]):
            stdin_lines.append(host)
        elif "port" in pt:
            stdin_lines.append(port)
        elif any(k in pt for k in ["user", "login"]):
            stdin_lines.append(user)
        elif any(k in pt for k in ["pass", "password"]):
            stdin_lines.append(password)
        elif "site" in pt:
            stdin_lines.append(site)
        else:
            stdin_lines.append("")   # unknown prompt — send empty line

    stdin = ("\n".join(stdin_lines) + "\n") if stdin_lines else None
    return cmd, stdin


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

def run_subprocess(
    cmd: list[str],
    stdin: str | None,
    timeout: int = 90,
) -> tuple[int, str]:
    """Run cmd, optionally piping stdin. Return (exit_code, combined_output)."""
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        combined = (result.stdout + result.stderr).strip()
        return result.returncode, combined
    except subprocess.TimeoutExpired:
        return 3, f"PoC timed out after {timeout}s"
    except FileNotFoundError as exc:
        return 3, f"Interpreter not found: {exc}"
    except Exception as exc:      # noqa: BLE001
        return 3, str(exc)


# ---------------------------------------------------------------------------
# Confirmation check
# ---------------------------------------------------------------------------

# Signatures for common probe files
_FILE_SIGNATURES: list[tuple[str, str]] = [
    ("/etc/passwd",  "root:"),
    ("/etc/shadow",  "root:"),
    ("/etc/hosts",   "127.0.0.1"),
    ("/proc/version","Linux version"),
    ("/etc/os-release", "NAME="),
    ("/windows/win.ini", "[fonts]"),
    ("/boot.ini",    "[boot loader]"),
]

_ERROR_SIGNALS = [
    "authentication error",
    "login failed",
    "access denied",
    "permission denied",
    "traceback (most recent",
    "error:",
    "exception:",
    "invalid credentials",
    "unauthorized",
]


def check_confirmed(exit_code: int, output: str, probe_file: str) -> bool:
    """Return True if the exploit confirmed the vulnerability."""
    out_lower = output.lower()

    # 1. Check known file-content signatures
    for path_key, sig in _FILE_SIGNATURES:
        if path_key in probe_file and sig.lower() in out_lower:
            return True

    # 2. Generic: process exited 0, produced meaningful content, no error header
    if exit_code == 0 and len(output.strip()) > 80:
        if not any(err in out_lower[:300] for err in _ERROR_SIGNALS):
            return True

    # 3. Explicit success markers many PoCs print
    success_markers = [
        "[+] success",
        "[+] confirmed",
        "[*] file content",
        "root:x:0:0",
        "[+] exploit",
    ]
    if any(m in out_lower for m in success_markers):
        return True

    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMENDER M1 – Language-Agnostic PoC Runner"
    )
    parser.add_argument("--poc",        required=True, help="Path to PoC file")
    parser.add_argument("--target",     required=True, help="Base URL of the target")
    parser.add_argument("--user",       default="admin", help="Username")
    parser.add_argument("--password",   default=None,
                        help="Password (or set AMENDER_PASSWORD env var)")
    parser.add_argument("--site",       default="default", help="Site ID")
    parser.add_argument("--probe-file", default="/etc/passwd",
                        dest="probe_file", help="Remote file to read as proof")
    parser.add_argument("--timeout",    type=int, default=90,
                        help="PoC subprocess timeout in seconds (default: 90)")
    args = parser.parse_args()

    password = (
        args.password
        or os.environ.get("AMENDER_PASSWORD")
        or getpass.getpass(f"[M1] Password for '{args.user}' on {args.target}: ")
    )

    poc_path = Path(args.poc).expanduser().resolve()
    if not poc_path.exists():
        print(f"[M1] ERROR: PoC not found: {poc_path}", file=sys.stderr)
        sys.exit(3)

    # ── Detect language ───────────────────────────────────────────────────────
    interpreter, reason = detect_interpreter(poc_path)
    if not shutil.which(interpreter):
        print(f"[M1] ERROR: '{interpreter}' not found in PATH (needed for {poc_path.name})",
              file=sys.stderr)
        sys.exit(3)
    print(f"[M1] PoC language: {interpreter}  (detected via {reason})")

    # ── Read source + build command ────────────────────────────────────────────
    source = poc_path.read_text(encoding="utf-8", errors="replace")
    cmd, stdin = build_command(
        interpreter, poc_path, source,
        args.target, args.user, password, args.probe_file, args.site,
    )
    print(f"[M1] Command: {_redact(' '.join(cmd))}")
    if stdin:
        print(f"[M1] Stdin:   {_redact(stdin.strip()[:120])} …")

    # ── Run PoC ───────────────────────────────────────────────────────────────
    ts_start = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"[M1] Running PoC …")
    exit_code, output = run_subprocess(cmd, stdin, timeout=args.timeout)
    print(f"[M1] exit_code={exit_code}")
    print(f"[M1] output (first 400 chars):\n{output[:400]}")

    # ── Determine verdict ──────────────────────────────────────────────────────
    if exit_code == 3:
        verdict = "ENV_ERROR"
    elif check_confirmed(exit_code, output, args.probe_file):
        verdict = "CONFIRMED"
        exit_code = 0
    else:
        verdict = "FAIL"
        exit_code = 2

    print(f"\n[M1] Verdict: {verdict}")

    _log_entry(
        cve=poc_path.stem,         # best-effort; caller can post-process
        stage="poc_run",
        iteration=1,
        poc_path=str(poc_path),
        timestamp=ts_start,
        input_state_sha="",
        command_run=_redact(" ".join(cmd)),
        exit_code=exit_code,
        output_snippet=_redact(output[:400]),
        llm_diagnosis=None,
        change_made=None,
        result=verdict,
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
