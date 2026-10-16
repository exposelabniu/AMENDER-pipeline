#!/usr/bin/env python3
"""
AMENDER M7 – Training Log Dashboard
=====================================
Reads  logs/training/amender.jsonl  and produces:

  1. A terminal summary (always)
  2. logs/dashboard.html  — self-contained HTML dashboard
                            (no CDN, no external dependencies)

Usage:
    python3 src/dashboard.py [--log logs/training/amender.jsonl]
                             [--out logs/dashboard.html]
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def load_entries(log_path: Path) -> list[dict]:
    entries: list[dict] = []
    if not log_path.exists():
        return entries
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def group_by_cve(entries: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        grouped[e.get("cve", "UNKNOWN")].append(e)
    return dict(grouped)


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------

def stage_entries(cve_entries: list[dict], stage: str) -> list[dict]:
    return [e for e in cve_entries if e.get("stage") == stage]


def _last_result(entries: list[dict]) -> str:
    for e in reversed(entries):
        r = e.get("result", "")
        if r:
            return r
    return "—"


def cve_stats(cve: str, entries: list[dict]) -> dict:
    poc_runs    = stage_entries(entries, "poc_run")
    poc_correct = stage_entries(entries, "poc_correction")
    m4_chi1     = stage_entries(entries, "module_gate_chi1")
    m4_chi2     = stage_entries(entries, "module_gate_chi2")
    mod_correct = stage_entries(entries, "module_correction")

    confirmed_poc = any(e.get("result") == "CONFIRMED" for e in poc_runs + poc_correct)
    confirmed_mod = any(e.get("result") == "CONFIRMED" for e in m4_chi1 + m4_chi2 + mod_correct)

    return {
        "cve":              cve,
        "total":            len(entries),
        "poc_iters":        len(poc_correct),
        "poc_result":       _last_result(poc_runs + poc_correct) if (poc_runs or poc_correct) else "—",
        "poc_confirmed":    confirmed_poc,
        "m4_chi1_result":  _last_result(m4_chi1) if m4_chi1 else "—",
        "m4_chi2_result":  _last_result(m4_chi2) if m4_chi2 else "—",
        "mod_iters":        len(mod_correct),
        "mod_result":       _last_result(mod_correct) if mod_correct else "—",
        "mod_confirmed":    confirmed_mod,
        "all_entries":      entries,
    }


# ---------------------------------------------------------------------------
# Terminal summary
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"


def _c(text: str, *codes: str) -> str:
    if sys.stdout.isatty():
        return "".join(codes) + text + _RESET
    return text


def print_terminal(grouped: dict[str, list[dict]]) -> None:
    total_entries = sum(len(v) for v in grouped.values())
    cves_ok = sum(
        1 for entries in grouped.values()
        if any(e.get("result") == "CONFIRMED" for e in entries)
    )

    print()
    print(_c("╔══════════════════════════════════════════════════╗", _BOLD))
    print(_c("║       AMENDER  –  Training Log Dashboard         ║", _BOLD))
    print(_c("╚══════════════════════════════════════════════════╝", _BOLD))
    print(f"  CVEs logged  : {_c(str(len(grouped)), _BOLD, _CYAN)}")
    print(f"  Confirmed    : {_c(str(cves_ok), _BOLD, _GREEN)}/{len(grouped)}")
    print(f"  Total entries: {total_entries}")
    print()

    for cve, entries in sorted(grouped.items()):
        s = cve_stats(cve, entries)
        ok_sym = _c("✓", _BOLD, _GREEN) if s["poc_confirmed"] or s["mod_confirmed"] else _c("✗", _BOLD, _RED)
        print(f"  {ok_sym}  {_c(cve, _BOLD)}")

        # PoC
        poc_col = _GREEN if s["poc_confirmed"] else _RED if s["poc_result"] not in ("—", "CONFIRMED") else _YELLOW
        print(f"       PoC      : {_c(s['poc_result'], poc_col)}  "
              f"({s['poc_iters']} correction iter{'s' if s['poc_iters'] != 1 else ''})")

        # Module gates
        g1 = _GREEN if s["m4_chi1_result"] == "PASS" else _RED if s["m4_chi1_result"] == "FAIL" else _YELLOW
        g2 = _GREEN if s["m4_chi2_result"] == "PASS" else _RED if s["m4_chi2_result"] == "FAIL" else _YELLOW
        print(f"       χ₁/χ₂    : {_c(s['m4_chi1_result'], g1)} / {_c(s['m4_chi2_result'], g2)}")

        # Module correction
        if s["mod_iters"]:
            mc = _GREEN if s["mod_confirmed"] else _RED
            print(f"       Module   : {_c(s['mod_result'], mc)}  "
                  f"({s['mod_iters']} correction iter{'s' if s['mod_iters'] != 1 else ''})")

        # Quick correction history
        poc_c  = stage_entries(entries, "poc_correction")
        mod_c  = stage_entries(entries, "module_correction")
        if poc_c or mod_c:
            print(f"       {_c('Correction history:', _DIM)}")
            for e in (poc_c + mod_c)[:10]:
                ts    = e.get("timestamp", "")[:16]
                res   = e.get("result", "?")
                stg   = e.get("stage", "?")
                it    = e.get("iteration", "?")
                color = _GREEN if res == "CONFIRMED" else _RED if res in ("EXHAUSTED","ENV_ERROR") else ""
                print(f"         {_c(ts, _DIM)}  [{stg}] iter {it}  → {_c(res, color)}")
            if len(poc_c + mod_c) > 10:
                print(f"         {_c(f'  … and {len(poc_c)+len(mod_c)-10} more', _DIM)}")

        print()

    print()


# ---------------------------------------------------------------------------
# HTML dashboard — zero external deps
# ---------------------------------------------------------------------------

_H = html.escape          # shortcut


def _bar(pct: float, color: str = "#4ade80", bg: str = "#1e293b") -> str:
    """Render a simple inline progress bar."""
    pct = max(0.0, min(100.0, pct))
    return (
        f'<div style="background:{bg};border-radius:4px;height:10px;width:100%;">'
        f'<div style="background:{color};border-radius:4px;height:10px;width:{pct:.1f}%;"></div>'
        f'</div>'
    )


def _badge(text: str, ok: bool | None = None) -> str:
    if ok is True:
        bg, fg = "#166534", "#bbf7d0"
    elif ok is False:
        bg, fg = "#7f1d1d", "#fecaca"
    else:
        bg, fg = "#1e3a5f", "#bae6fd"
    return (f'<span style="background:{bg};color:{fg};padding:2px 8px;'
            f'border-radius:999px;font-size:0.78rem;font-weight:600;">'
            f'{_H(text)}</span>')


def _row_color(result: str) -> str:
    if result == "CONFIRMED":
        return "background:rgba(74,222,128,0.06);"
    if result in ("EXHAUSTED", "ENV_ERROR", "FAIL"):
        return "background:rgba(248,113,113,0.07);"
    return ""


def build_html(grouped: dict[str, list[dict]]) -> str:
    total  = sum(len(v) for v in grouped.values())
    n_cves = len(grouped)
    n_ok   = sum(
        1 for e in grouped.values()
        if any(x.get("result") == "CONFIRMED" for x in e)
    )
    success_rate = (n_ok / n_cves * 100) if n_cves else 0.0

    # ── Aggregate stage counts for summary chart ──────────────────────────
    stage_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for entries in grouped.values():
        for e in entries:
            stg = e.get("stage", "other")
            res = e.get("result", "other")
            stage_counts[stg][res] += 1

    def sc(stage: str, result: str) -> int:
        return stage_counts[stage].get(result, 0)

    # ── Build per-CVE sections ────────────────────────────────────────────
    cve_sections = []
    for cve, entries in sorted(grouped.items()):
        s = cve_stats(cve, entries)

        overall_ok   = s["poc_confirmed"] or s["mod_confirmed"]
        overall_badge = _badge("CONFIRMED", True) if overall_ok else _badge("PENDING", None)

        poc_c  = stage_entries(entries, "poc_correction")
        mod_c  = stage_entries(entries, "module_correction")
        all_c  = poc_c + mod_c

        # Correction history table
        rows = []
        for e in all_c:
            ts     = _H(e.get("timestamp", "")[:19].replace("T", " "))
            stg    = _H(e.get("stage", ""))
            it     = _H(str(e.get("iteration", "")))
            sha    = _H(str(e.get("input_state_sha", ""))[:8])
            res    = e.get("result", "")
            exit_c = _H(str(e.get("exit_code", "")))
            diag   = _H((e.get("llm_diagnosis") or "")[:200])
            change = _H((e.get("change_made") or "")[:150])
            res_ok = True if res == "CONFIRMED" else (False if res in ("EXHAUSTED","ENV_ERROR","FAIL") else None)
            rows.append(
                f'<tr style="{_row_color(res)}">'
                f'<td>{ts}</td>'
                f'<td>{stg}</td>'
                f'<td style="text-align:center">{it}</td>'
                f'<td style="text-align:center">{sha}</td>'
                f'<td style="text-align:center">{exit_c}</td>'
                f'<td>{_badge(res, res_ok)}</td>'
                f'<td><details><summary style="cursor:pointer;font-size:0.78rem;">show</summary>'
                f'<pre style="white-space:pre-wrap;font-size:0.72rem;margin-top:4px;">{diag}</pre></details></td>'
                f'<td><details><summary style="cursor:pointer;font-size:0.78rem;">diff</summary>'
                f'<pre style="white-space:pre-wrap;font-size:0.72rem;margin-top:4px;">{change}</pre></details></td>'
                f'</tr>'
            )
        history_html = (
            '<table class="log-table"><thead><tr>'
            '<th>Timestamp</th><th>Stage</th><th>Iter</th><th>SHA</th>'
            '<th>Exit</th><th>Result</th><th>LLM Diagnosis</th><th>Diff</th>'
            '</tr></thead><tbody>' + "\n".join(rows) + '</tbody></table>'
            if rows else '<p style="color:#64748b;font-size:0.85rem;">No correction iterations logged.</p>'
        )

        # Gate badges
        chi1_ok = s["m4_chi1_result"] == "PASS"
        chi2_ok = s["m4_chi2_result"] == "PASS"

        cve_sections.append(f"""
<section class="cve-card">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">
    <h2 style="margin:0;font-size:1.15rem;">{_H(cve)}</h2>
    {overall_badge}
    <span style="margin-left:auto;color:#64748b;font-size:0.8rem;">{s['total']} log entries</span>
  </div>

  <div class="stat-grid">
    <div class="stat-box">
      <div class="stat-label">PoC result</div>
      <div class="stat-val">{_badge(s['poc_result'], s['poc_confirmed'])}</div>
      <div class="stat-sub">{s['poc_iters']} correction iter{'s' if s['poc_iters']!=1 else ''}</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">χ₁ ruby -c</div>
      <div class="stat-val">{_badge(s['m4_chi1_result'], chi1_ok if s['m4_chi1_result'] != '—' else None)}</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">χ₂ msftidy</div>
      <div class="stat-val">{_badge(s['m4_chi2_result'], chi2_ok if s['m4_chi2_result'] != '—' else None)}</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">Module result</div>
      <div class="stat-val">{_badge(s['mod_result'] if s['mod_result'] != '—' else 'n/a', s['mod_confirmed'] if s['mod_result'] != '—' else None)}</div>
      <div class="stat-sub">{s['mod_iters']} correction iter{'s' if s['mod_iters']!=1 else ''}</div>
    </div>
  </div>

  <details {"open" if all_c else ""}>
    <summary style="cursor:pointer;margin:16px 0 10px;font-weight:600;font-size:0.88rem;color:#94a3b8;">
      Correction history ({len(all_c)} iteration{'s' if len(all_c)!=1 else ''})
    </summary>
    {history_html}
  </details>
</section>
""")

    # ── Stage summary bar chart (pure CSS) ───────────────────────────────
    bar_stages = [
        ("poc_run",          "PoC run"),
        ("poc_correction",   "PoC correction"),
        ("module_gate_chi1", "χ₁ gate"),
        ("module_gate_chi2", "χ₂ gate"),
        ("module_correction","Module correction"),
    ]
    bar_rows = []
    for stg_key, stg_label in bar_stages:
        total_stg = sum(stage_counts[stg_key].values())
        if total_stg == 0:
            continue
        confirmed = sc(stg_key, "CONFIRMED") + sc(stg_key, "PASS")
        failed    = sc(stg_key, "FAIL") + sc(stg_key, "EXHAUSTED") + sc(stg_key, "ENV_ERROR")
        ok_pct    = confirmed / total_stg * 100
        fail_pct  = failed    / total_stg * 100
        bar_rows.append(f"""
    <tr>
      <td style="white-space:nowrap;padding-right:16px;color:#94a3b8;font-size:0.82rem;">{_H(stg_label)}</td>
      <td style="width:100%;">
        <div style="display:flex;height:14px;border-radius:4px;overflow:hidden;background:#1e293b;">
          <div style="width:{ok_pct:.1f}%;background:#4ade80;" title="Pass/Confirmed: {confirmed}"></div>
          <div style="width:{fail_pct:.1f}%;background:#f87171;" title="Fail/Exhausted: {failed}"></div>
        </div>
      </td>
      <td style="padding-left:12px;white-space:nowrap;font-size:0.78rem;color:#64748b;">
        {confirmed} ok / {failed} fail / {total_stg} total
      </td>
    </tr>""")

    chart_html = f"""
<section class="cve-card">
  <h2 style="margin:0 0 14px;font-size:1.05rem;">Stage pass / fail overview</h2>
  <table style="width:100%;border-collapse:collapse;">
    {"".join(bar_rows)}
  </table>
  <div style="margin-top:10px;display:flex;gap:16px;font-size:0.75rem;color:#64748b;">
    <span><span style="display:inline-block;width:10px;height:10px;background:#4ade80;border-radius:2px;margin-right:4px;"></span>Pass / Confirmed</span>
    <span><span style="display:inline-block;width:10px;height:10px;background:#f87171;border-radius:2px;margin-right:4px;"></span>Fail / Exhausted</span>
    <span><span style="display:inline-block;width:10px;height:10px;background:#1e293b;border-radius:2px;margin-right:4px;border:1px solid #334155;"></span>Other</span>
  </div>
</section>
"""

    # ── Full HTML ─────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AMENDER Dashboard</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: ui-monospace, "Cascadia Code", "Fira Code", Consolas, monospace;
    background: #0f172a;
    color: #e2e8f0;
    min-height: 100vh;
    padding: 24px 16px 48px;
  }}
  header {{
    max-width: 960px;
    margin: 0 auto 28px;
    padding-bottom: 18px;
    border-bottom: 1px solid #1e293b;
  }}
  header h1 {{
    font-size: 1.4rem;
    letter-spacing: .04em;
    color: #f1f5f9;
  }}
  header p {{ color: #64748b; font-size: 0.82rem; margin-top: 4px; }}
  .top-stats {{
    max-width: 960px;
    margin: 0 auto 24px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
  }}
  .kpi {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 14px 16px;
  }}
  .kpi-label {{ font-size: 0.72rem; color: #64748b; text-transform: uppercase; letter-spacing: .06em; }}
  .kpi-val   {{ font-size: 2rem; font-weight: 700; color: #f1f5f9; line-height: 1.1; margin-top: 4px; }}
  .kpi-sub   {{ font-size: 0.75rem; color: #94a3b8; margin-top: 2px; }}
  main {{
    max-width: 960px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }}
  .cve-card {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px 22px;
  }}
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 10px;
  }}
  .stat-box {{
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 10px 12px;
  }}
  .stat-label {{ font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing:.05em; }}
  .stat-val   {{ margin: 6px 0 4px; }}
  .stat-sub   {{ font-size: 0.7rem; color: #475569; }}
  .log-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.78rem;
    margin-top: 8px;
  }}
  .log-table th {{
    background: #0f172a;
    color: #64748b;
    text-align: left;
    padding: 6px 8px;
    border-bottom: 1px solid #334155;
    white-space: nowrap;
  }}
  .log-table td {{
    padding: 6px 8px;
    border-bottom: 1px solid #1e293b;
    vertical-align: top;
    color: #cbd5e1;
  }}
  .log-table tr:hover td {{ background: rgba(255,255,255,0.02); }}
  details > summary {{ list-style: none; }}
  details > summary::before {{ content: "▶ "; }}
  details[open] > summary::before {{ content: "▼ "; }}
  pre {{ font-family: inherit; }}
  @media (max-width: 600px) {{
    .log-table {{ font-size: 0.68rem; }}
    .log-table th, .log-table td {{ padding: 4px 5px; }}
  }}
</style>
</head>
<body>

<header>
  <h1>⚡ AMENDER – Training Log Dashboard</h1>
  <p>Source: <code>logs/training/amender.jsonl</code> &nbsp;·&nbsp; {total} log entries across {n_cves} CVE{'s' if n_cves!=1 else ''}</p>
</header>

<div class="top-stats">
  <div class="kpi">
    <div class="kpi-label">CVEs</div>
    <div class="kpi-val">{n_cves}</div>
    <div class="kpi-sub">in training log</div>
  </div>
  <div class="kpi">
    <div class="kpi-label">Confirmed</div>
    <div class="kpi-val" style="color:#4ade80;">{n_ok}</div>
    <div class="kpi-sub">end-to-end pass</div>
  </div>
  <div class="kpi">
    <div class="kpi-label">Success rate</div>
    <div class="kpi-val" style="color:#{'4ade80' if success_rate >= 80 else 'fbbf24' if success_rate >= 50 else 'f87171'};">{success_rate:.0f}%</div>
    <div class="kpi-sub">{_bar(success_rate)}</div>
  </div>
  <div class="kpi">
    <div class="kpi-label">Log entries</div>
    <div class="kpi-val">{total}</div>
    <div class="kpi-sub">total JSONL rows</div>
  </div>
</div>

<main>
  {chart_html}
  {"".join(cve_sections)}
</main>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMENDER M7 – Dashboard over logs/training/amender.jsonl"
    )
    parser.add_argument(
        "--log", default="logs/training/amender.jsonl",
        help="Path to the JSONL training log (default: logs/training/amender.jsonl)"
    )
    parser.add_argument(
        "--out", default="logs/dashboard.html",
        help="Output HTML file (default: logs/dashboard.html)"
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Print terminal summary only; do not write HTML"
    )
    args = parser.parse_args()

    log_path = Path(args.log).expanduser()
    out_path = Path(args.out).expanduser()

    entries = load_entries(log_path)
    if not entries:
        print(f"[M7] No entries found in {log_path}", file=sys.stderr)
        print("[M7] Run the AMENDER pipeline first to generate training data.")
        sys.exit(0)

    grouped = group_by_cve(entries)

    # Terminal output
    print_terminal(grouped)

    if args.no_html:
        return

    # HTML output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html_content = build_html(grouped)
    out_path.write_text(html_content, encoding="utf-8")
    print(f"[M7] Dashboard written → {out_path}")
    print(f"[M7] Open with:  python3 -m http.server --directory {out_path.parent} 8181")
    print(f"[M7]   then:     http://localhost:8181/{out_path.name}")


if __name__ == "__main__":
    main()
