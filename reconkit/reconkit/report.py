"""Write findings.json, report.md and report.html into the results folder.

WHY THREE FORMATS:
* findings.json - machine-readable, so you (or a future script) can compare runs.
* report.md     - readable in any text editor and renders nicely on GitHub.
* report.html   - open in a browser and share with someone who doesn't use a terminal.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from reconkit import __version__
from reconkit.findings import SEVERITIES, Finding, ModuleResult, count_by_severity, sort_findings
from reconkit.target import Target

DISCLAIMER = ("Automated scanners miss things and report false positives. Treat every finding as a "
              "lead to verify, not a confirmed vulnerability.")


def _all_findings(results: list[ModuleResult]) -> list[Finding]:
    return sort_findings([f for r in results for f in r.findings])


def write_reports(outdir: Path, target: Target, results: list[ModuleResult],
                  started: datetime, finished: datetime) -> dict[str, Path]:
    paths = {
        "json": outdir / "findings.json",
        "markdown": outdir / "report.md",
        "html": outdir / "report.html",
    }
    paths["json"].write_text(json.dumps({
        "target": target.host,
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "reconkit_version": __version__,
        "modules": [r.to_dict() for r in results],
    }, indent=2), encoding="utf-8")
    paths["markdown"].write_text(render_markdown(target, results, started, finished), encoding="utf-8")
    paths["html"].write_text(render_html(target, results, started, finished), encoding="utf-8")
    return paths


def render_markdown(target: Target, results: list[ModuleResult], started: datetime, finished: datetime) -> str:
    findings = _all_findings(results)
    counts = count_by_severity(findings)
    lines = [
        f"# reconkit report: {target.host}",
        "",
        f"- **Target:** `{target.original}`",
        f"- **Scan window:** {started:%Y-%m-%d %H:%M:%S} to {finished:%H:%M:%S} (local time)",
        f"- **reconkit version:** {__version__}",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        *[f"| {s.title()} | {counts[s]} |" for s in SEVERITIES],
        "",
        "## Modules",
        "",
        "| Module | Status | Command / note |",
        "|---|---|---|",
    ]
    for r in results:
        status = "ran" if r.ran else "skipped"
        detail = r.command if r.ran else r.note
        lines.append(f"| {r.module} | {status} | `{detail}` |" if detail else f"| {r.module} | {status} | |")
    lines += ["", "## Findings (most severe first)", ""]
    if not findings:
        lines.append("_No findings._")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{f.severity.upper()}] {f.title}",
            "",
            f"*Module: {f.module}*",
            "",
        ]
        if f.evidence:
            lines += [f"**Evidence:** `{f.evidence}`", ""]
        lines += [
            f"**What this means:** {f.what_it_means}",
            "",
            f"**Why it matters:** {f.why_it_matters}",
            "",
            f"**Suggested next step:** {f.next_step}",
            "",
        ]
        if f.references:
            lines += ["**Learn more:** " + ", ".join(f.references), ""]
    return "\n".join(lines) + "\n"


_SEV_COLORS = {"critical": "#7b1fa2", "high": "#c62828", "medium": "#ef6c00", "low": "#0277bd", "info": "#616161"}


def render_html(target: Target, results: list[ModuleResult], started: datetime, finished: datetime) -> str:
    # html.escape() is essential: tool output comes from the TARGET, which could be
    # hostile. Without escaping, a server could put <script> in its banner and run
    # JavaScript in your browser when you open the report (stored XSS!).
    e = html.escape
    findings = _all_findings(results)
    counts = count_by_severity(findings)
    summary = "".join(
        f'<span class="pill" style="background:{_SEV_COLORS[s]}">{s.title()}: {counts[s]}</span>'
        for s in SEVERITIES)
    modules = "".join(
        f"<tr><td>{e(r.module)}</td><td>{'ran' if r.ran else 'skipped'}</td>"
        f"<td><code>{e(r.command if r.ran else r.note)}</code></td></tr>" for r in results)
    cards = []
    for f in findings:
        refs = "".join(f'<li><a href="{e(u)}">{e(u)}</a></li>' for u in f.references)
        cards.append(f"""
<section class="card" style="border-left-color:{_SEV_COLORS.get(f.severity, '#616161')}">
  <h3><span class="sev" style="background:{_SEV_COLORS.get(f.severity, '#616161')}">{e(f.severity.upper())}</span> {e(f.title)}</h3>
  <p class="meta">Module: {e(f.module)}</p>
  {f'<p><b>Evidence:</b> <code>{e(f.evidence)}</code></p>' if f.evidence else ''}
  <p><b>What this means:</b> {e(f.what_it_means)}</p>
  <p><b>Why it matters:</b> {e(f.why_it_matters)}</p>
  <p><b>Suggested next step:</b> {e(f.next_step)}</p>
  {f'<p><b>Learn more:</b></p><ul>{refs}</ul>' if refs else ''}
</section>""")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>reconkit report: {e(target.host)}</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #222; line-height: 1.5; }}
 code {{ background: #f3f3f3; padding: 0 .25rem; word-break: break-word; }}
 table {{ border-collapse: collapse; width: 100%; }} td, th {{ border: 1px solid #ddd; padding: .4rem; text-align: left; }}
 .pill, .sev {{ color: #fff; border-radius: 4px; padding: .1rem .5rem; margin-right: .4rem; font-size: .85rem; }}
 .card {{ border: 1px solid #ddd; border-left: 6px solid; border-radius: 6px; padding: .5rem 1rem; margin: 1rem 0; }}
 .meta {{ color: #666; font-size: .9rem; margin-top: -.5rem; }}
 .note {{ background: #fff8e1; padding: .5rem 1rem; border-radius: 6px; }}
</style></head><body>
<h1>reconkit report: {e(target.host)}</h1>
<p>Target <code>{e(target.original)}</code> &middot; {started:%Y-%m-%d %H:%M:%S} to {finished:%H:%M:%S} (local) &middot; reconkit {e(__version__)}</p>
<p class="note">{e(DISCLAIMER)}</p>
<h2>Summary</h2><p>{summary}</p>
<h2>Modules</h2><table><tr><th>Module</th><th>Status</th><th>Command / note</th></tr>{modules}</table>
<h2>Findings (most severe first)</h2>
{''.join(cards) if cards else '<p><i>No findings.</i></p>'}
</body></html>
"""
