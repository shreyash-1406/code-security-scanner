"""Turns findings into console, JSON, or HTML output."""

import html
import json
from collections import Counter
from datetime import datetime

from .scanner import security_score, grade

COLOURS = {
    "CRITICAL": "\033[1;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m", "INFO": "\033[0;37m",
}
RESET = "\033[0m"


def summary(findings, scanned):
    sec = [f for f in findings if f.category == "security"]
    qual = [f for f in findings if f.category == "quality"]
    score = security_score(findings)
    return {
        "files_scanned": scanned,
        "security_findings": len(sec),
        "quality_findings": len(qual),
        "by_severity": dict(Counter(f.severity for f in sec)),
        "score": score,
        "grade": grade(score),
    }


def to_console(findings, scanned, colour=True):
    out = []
    for f in findings:
        sev = f"{COLOURS[f.severity]}{f.severity:<8}{RESET}" if colour else f"{f.severity:<8}"
        tag = f" [{f.cwe}]" if f.cwe else ""
        out.append(f"{sev} {f.rule_id} {f.title}{tag}")
        out.append(f"         {f.file}:{f.line}")
        if f.code:
            out.append(f"         > {f.code}")
        out.append(f"         Fix: {f.recommendation}")
        out.append("")

    s = summary(findings, scanned)
    out.append("=" * 60)
    out.append(f"Files scanned     : {s['files_scanned']}")
    out.append(f"Security findings : {s['security_findings']}  {s['by_severity']}")
    out.append(f"Quality findings  : {s['quality_findings']}")
    out.append(f"Security score    : {s['score']}/100  (grade {s['grade']})")
    return "\n".join(out)


def to_json(findings, scanned):
    return json.dumps({
        "generated": datetime.now().isoformat(timespec="seconds"),
        "summary": summary(findings, scanned),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def to_html(findings, scanned, target):
    s = summary(findings, scanned)
    rows = []
    for f in findings:
        rows.append(
            "<tr class='{sev}'><td><span class='badge {sev}'>{sev}</span></td>"
            "<td>{cat}</td><td><b>{rid}</b> {title}<br><small>{cwe}</small></td>"
            "<td><code>{file}:{line}</code><pre>{code}</pre></td><td>{rec}</td></tr>".format(
                sev=f.severity, cat=f.category, rid=f.rule_id, title=html.escape(f.title),
                cwe=f.cwe, file=html.escape(f.file), line=f.line,
                code=html.escape(f.code), rec=html.escape(f.recommendation)))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>secscan report</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f1117;color:#e6e6e6}}
 h1{{margin:0 0 .3rem}} .muted{{color:#9aa0a6}}
 .cards{{display:flex;gap:1rem;margin:1.5rem 0;flex-wrap:wrap}}
 .card{{background:#1a1d27;padding:1rem 1.4rem;border-radius:10px;min-width:140px}}
 .card b{{display:block;font-size:1.8rem}}
 table{{width:100%;border-collapse:collapse;background:#1a1d27;border-radius:10px;overflow:hidden}}
 th,td{{padding:.6rem;border-bottom:1px solid #2a2e3a;vertical-align:top;text-align:left;font-size:.9rem}}
 pre{{white-space:pre-wrap;margin:.3rem 0 0;color:#c3e88d}}
 .badge{{padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}}
 .badge.CRITICAL{{background:#b71c1c}} .badge.HIGH{{background:#e53935}}
 .badge.MEDIUM{{background:#f9a825;color:#000}} .badge.LOW{{background:#00838f}}
 .badge.INFO{{background:#546e7a}}
</style></head><body>
<h1>Code Security &amp; Quality Report</h1>
<div class="muted">Target: {html.escape(target)} &middot; {datetime.now():%Y-%m-%d %H:%M}</div>
<div class="cards">
 <div class="card">Score<b>{s['score']}/100</b>Grade {s['grade']}</div>
 <div class="card">Files<b>{s['files_scanned']}</b></div>
 <div class="card">Security<b>{s['security_findings']}</b></div>
 <div class="card">Quality<b>{s['quality_findings']}</b></div>
</div>
<table><thead><tr><th>Severity</th><th>Type</th><th>Issue</th><th>Location</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=5>No findings 🎉</td></tr>'}</tbody></table>
</body></html>"""
