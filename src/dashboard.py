#!/usr/bin/env python3
"""AMENDER Dashboard — per-CVE correction history, auto-grouped from amender.jsonl."""

import json
import argparse
from pathlib import Path
from html import escape as _H
from collections import OrderedDict


# ── helpers ────────────────────────────────────────────────────────────────

def _badge(ok: bool) -> str:
    if ok:
        return '<span class="badge badge-pass">PASS</span>'
    return '<span class="badge badge-fail">FAIL</span>'


def _stage_label(stage: str) -> str:
    return {
        'poc_run':           'M1 PoC Run',
        'poc_correction':    'M3 PoC Fix',
        'module_gen':        'M4 Gen',
        'module_correction': 'M5 Mod Fix',
        'live_test':         '7b Live',
        'live_correction':   '7c Live Fix',
    }.get(stage, stage)


def _row_bg(result: str) -> str:
    if result == 'CONFIRMED':
        return 'style="background:rgba(20,83,45,0.35);"'
    if result in ('EXHAUSTED', 'ENV_ERROR', 'FAIL', 'PATCH_FAIL'):
        return 'style="background:rgba(127,29,29,0.35);"'
    return ''


def load_logs(path: Path):
    entries = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def group_by_cve(entries):
    groups = OrderedDict()
    for e in entries:
        cve = e.get('cve', 'UNKNOWN')
        if cve not in groups:
            groups[cve] = []
        groups[cve].append(e)
    return groups


def load_config(root: Path, cve_id: str) -> dict:
    slug = cve_id.lower().replace('-', '_')
    p = root / 'data' / f'{slug}.json'
    if p.exists():
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            pass
    return {}


# ── per-CVE history table ──────────────────────────────────────────────────

def build_history_table(entries: list) -> str:
    rows = []
    for e in entries:
        ts     = _H(e.get('timestamp', '')[:19].replace('T', ' '))
        stg    = _H(_stage_label(e.get('stage', '')))
        it     = _H(str(e.get('iteration', '')))
        sha    = _H(str(e.get('input_state_sha', ''))[:8])
        res    = e.get('result', '')
        diag   = _H((e.get('llm_diagnosis') or '').strip())
        change = _H((e.get('change_made') or '').strip())

        ok         = (res == 'CONFIRMED')
        badge_html = _badge(ok)

        parts = []
        if diag:
            parts.append('<span class="lbl-err">ERROR FOUND</span><br>' + diag)
        if change:
            parts.append('<span class="lbl-fix">CHANGES MADE</span><br>' + change)
        comment_html = '<hr class="sep">'.join(parts) if parts \
                       else '<span class="muted">—</span>'

        diff_html = (
            '<details><summary class="show-btn">&#9656; show</summary>'
            f'<pre class="diff-pre">{change}</pre>'
            '</details>'
        ) if change else '<span class="muted">—</span>'

        rows.append(
            f'<tr {_row_bg(res)}>'
            f'<td class="nowrap">{ts}</td>'
            f'<td>{stg}</td>'
            f'<td class="center">{it}</td>'
            f'<td class="center mono">{sha}</td>'
            f'<td class="center">{badge_html}</td>'
            f'<td class="comment-cell">{comment_html}</td>'
            f'<td>{diff_html}</td>'
            '</tr>'
        )

    if not rows:
        return '<p class="no-data">No log entries for this CVE.</p>'

    return (
        '<table class="log-table">'
        '<thead><tr>'
        '<th>Timestamp</th><th>Stage</th><th>Iteration</th><th>SHA</th>'
        '<th>Result</th><th>Comments</th><th>Difference</th>'
        '</tr></thead>'
        '<tbody>' + '\n'.join(rows) + '</tbody>'
        '</table>'
    )


# ── per-CVE card ───────────────────────────────────────────────────────────

def build_cve_card(cve_id: str, entries: list, config: dict) -> str:
    vuln_class = config.get('vuln_class', '')
    name       = config.get('name', '')
    edb        = config.get('edb', '')
    confirmed  = any(e.get('result') == 'CONFIRMED' for e in entries)
    total_iter = len(entries)
    first_ts   = entries[0].get('timestamp', '')[:10] if entries else ''

    status_cls = 'status-pass' if confirmed else 'status-fail'
    status_txt = 'CONFIRMED' if confirmed else 'NOT CONFIRMED'

    meta_parts = []
    if vuln_class:
        meta_parts.append(f'<span class="meta-tag meta-class">{_H(vuln_class)}</span>')
    if edb:
        meta_parts.append(f'<span class="meta-tag">EDB-{_H(str(edb))}</span>')
    if name:
        meta_parts.append(f'<span class="meta-tag">{_H(name[:70])}</span>')
    meta_html = ' '.join(meta_parts)

    table_html = build_history_table(entries)

    return f'''
<div class="cve-card">
  <div class="cve-header" onclick="toggle(this)">
    <div class="cve-title">
      <span class="cve-id">{_H(cve_id)}</span>
      <span class="{status_cls}">{status_txt}</span>
      {meta_html}
    </div>
    <div class="cve-meta-right">
      <span class="iter-count">{total_iter} entries</span>
      <span class="first-ts">{_H(first_ts)}</span>
      <span class="chevron">&#9660;</span>
    </div>
  </div>
  <div class="cve-body">
    {table_html}
  </div>
</div>'''


# ── CSS ────────────────────────────────────────────────────────────────────

CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #0a0f1e; color: #cbd5e1;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  font-size: 0.875rem; padding: 28px 32px;
}
h1 {
  font-size: 1.35rem; font-weight: 600; color: #e2e8f0;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: -0.01em;
  margin-bottom: 4px;
}
.subtitle { color: #475569; font-size: 0.75rem; margin-bottom: 24px; font-family: 'IBM Plex Mono', monospace; }

.summary-bar { display: flex; gap: 14px; margin-bottom: 28px; flex-wrap: wrap; }
.stat {
  background: #0f1a2e; border: 1px solid #1e293b;
  border-radius: 6px; padding: 14px 22px; min-width: 110px;
}
.stat-val {
  font-size: 1.65rem; font-weight: 600; color: #e2e8f0; line-height: 1.1;
  font-family: 'IBM Plex Mono', monospace;
}
.stat-lbl { font-size: 0.68rem; color: #64748b; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.08em; }
.stat.green .stat-val { color: #4ade80; }
.stat.red   .stat-val { color: #f87171; }
.stat.blue  .stat-val { color: #7dd3fc; }

.cve-card {
  background: #0d1525; border: 1px solid #1e293b;
  border-radius: 8px; margin-bottom: 12px; overflow: hidden;
}
.cve-header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 13px 18px; cursor: pointer; user-select: none;
  transition: background 0.12s;
}
.cve-header:hover { background: #131e35; }
.cve-title { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.cve-id {
  font-size: 0.95rem; font-weight: 600; color: #93c5fd;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: 0.02em;
}
.status-pass {
  background: #052e16; color: #4ade80;
  padding: 2px 10px; border-radius: 4px; font-size: 0.65rem; font-weight: 600;
  font-family: 'IBM Plex Mono', monospace; letter-spacing: 0.04em;
}
.status-fail {
  background: #2d0a0a; color: #f87171;
  padding: 2px 10px; border-radius: 4px; font-size: 0.65rem; font-weight: 600;
  font-family: 'IBM Plex Mono', monospace; letter-spacing: 0.04em;
}
.meta-tag {
  background: #1e293b; color: #94a3b8;
  padding: 2px 8px; border-radius: 3px; font-size: 0.67rem;
  font-family: 'IBM Plex Sans', sans-serif;
}
.meta-class { background: #1e3a5f; color: #7dd3fc; }
.cve-meta-right {
  display: flex; align-items: center; gap: 14px;
  color: #475569; font-size: 0.72rem;
  font-family: 'IBM Plex Mono', monospace;
}
.chevron { font-size: 0.7rem; color: #475569; transition: transform 0.2s; display: inline-block; }
.cve-card.open .chevron { transform: rotate(180deg); }
.cve-body { display: none; padding: 0 18px 20px; }
.cve-card.open .cve-body { display: block; }

.log-table { width: 100%; border-collapse: collapse; font-size: 0.75rem; margin-top: 10px; }
.log-table th {
  background: #111e33; color: #7dd3fc;
  text-align: left; padding: 8px 10px;
  border-bottom: 1px solid #1e293b;
  font-weight: 500; font-size: 0.65rem;
  text-transform: uppercase; letter-spacing: 0.07em;
  font-family: 'IBM Plex Sans', sans-serif;
}
.log-table td { padding: 8px 10px; border-bottom: 1px solid #131e33; vertical-align: top; }
.log-table tr:last-child td { border-bottom: none; }
.nowrap { white-space: nowrap; color: #94a3b8; font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; }
.center { text-align: center; }
.mono { font-family: 'IBM Plex Mono', monospace; font-size: 0.7rem; color: #94a3b8; }
.comment-cell { font-size: 0.72rem; max-width: 340px; line-height: 1.7; }
.lbl-err { color: #f87171; font-weight: 600; font-size: 0.63rem; text-transform: uppercase; letter-spacing: 0.07em; font-family: 'IBM Plex Mono', monospace; }
.lbl-fix { color: #4ade80; font-weight: 600; font-size: 0.63rem; text-transform: uppercase; letter-spacing: 0.07em; font-family: 'IBM Plex Mono', monospace; }
.sep { border: none; border-top: 1px solid #2d3f5c; margin: 7px 0; }
.muted { color: #475569; }
.badge { padding: 2px 9px; border-radius: 3px; font-size: 0.65rem; font-weight: 600; font-family: 'IBM Plex Mono', monospace; }
.badge-pass { background: #052e16; color: #4ade80; }
.badge-fail { background: #2d0a0a; color: #f87171; }
.show-btn { cursor: pointer; font-size: 0.7rem; color: #60a5fa; list-style: none; font-family: 'IBM Plex Mono', monospace; }
.show-btn:hover { color: #93c5fd; }
.diff-pre {
  white-space: pre-wrap;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 0.67rem; line-height: 1.55;
  margin-top: 8px; max-height: 200px; overflow-y: auto;
  background: #070c18; padding: 10px 12px;
  border-radius: 4px; border: 1px solid #1e293b;
}
.no-data { color: #475569; font-size: 0.78rem; padding: 12px 0; font-family: 'IBM Plex Mono', monospace; }
"""

JS = """
function toggle(header) {
  header.parentElement.classList.toggle('open');
}
document.addEventListener('DOMContentLoaded', function () {
  var first = document.querySelector('.cve-card');
  if (first) first.classList.add('open');
});
"""


# ── full HTML page ─────────────────────────────────────────────────────────

def build_html(groups: dict, root: Path, log_path: Path) -> str:
    total_cves = len(groups)
    confirmed  = sum(1 for ents in groups.values()
                     if any(e.get('result') == 'CONFIRMED' for e in ents))
    total_logs = sum(len(v) for v in groups.values())
    vuln_classes = set()
    for cve_id in groups:
        cfg = load_config(root, cve_id)
        vc = cfg.get('vuln_class', '')
        if vc:
            vuln_classes.add(vc)

    stats_html = f'''
<div class="summary-bar">
  <div class="stat blue"><div class="stat-val">{total_cves}</div><div class="stat-lbl">CVEs Tested</div></div>
  <div class="stat green"><div class="stat-val">{confirmed}</div><div class="stat-lbl">Confirmed</div></div>
  <div class="stat red"><div class="stat-val">{total_cves - confirmed}</div><div class="stat-lbl">Not Confirmed</div></div>
  <div class="stat"><div class="stat-val">{total_logs}</div><div class="stat-lbl">Log Entries</div></div>
  <div class="stat"><div class="stat-val">{len(vuln_classes)}</div><div class="stat-lbl">Vuln Classes</div></div>
</div>'''

    cards_html = ''
    for cve_id, ents in groups.items():
        config = load_config(root, cve_id)
        cards_html += build_cve_card(cve_id, ents, config)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AMENDER Dashboard</title>
<style>{CSS}</style>
</head>
<body>
<h1>AMENDER Dashboard</h1>
<p class="subtitle">Source: {_H(str(log_path))} &mdash; one card per CVE, auto-updated on each pipeline run</p>
{stats_html}
{cards_html}
<script>{JS}</script>
</body>
</html>'''


# ── entry point ────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='AMENDER per-CVE dashboard generator')
    ap.add_argument('--log', default='logs/training/amender.jsonl',
                    help='Path to amender.jsonl')
    ap.add_argument('--out', default='logs/dashboard.html',
                    help='Output HTML path')
    args = ap.parse_args()

    root     = Path(__file__).resolve().parent.parent
    log_path = Path(args.log)
    out_path = Path(args.out)

    if not log_path.exists():
        print(f'[ERROR] Log file not found: {log_path}')
        return 1

    entries = load_logs(log_path)
    groups  = group_by_cve(entries)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(build_html(groups, root, log_path), encoding='utf-8')

    print(f'[OK] Dashboard written -> {out_path}')
    print(f'     CVEs: {len(groups)}  |  Log entries: {len(entries)}')
    for cve_id, ents in groups.items():
        ok = any(e.get('result') == 'CONFIRMED' for e in ents)
        print(f'     {"OK" if ok else "XX"}  {cve_id}  ({len(ents)} entries)')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
