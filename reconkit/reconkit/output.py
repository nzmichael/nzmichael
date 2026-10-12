"""Everything to do with printing to the terminal and creating result folders.

Keeping display code in one place means the scanner modules never call print()
for findings themselves. That separation makes the modules easy to test: a test
can call a parser and inspect the returned Findings without any screen output.
"""

from __future__ import annotations

import os
import re
import sys
import textwrap
from datetime import datetime
from pathlib import Path

from reconkit.findings import Finding, ModuleResult, count_by_severity, sort_findings

# --- Colours -----------------------------------------------------------------
# ANSI escape codes are special character sequences that terminals interpret as
# "change colour". We only use them when output goes to a real terminal: if you
# redirect output to a file (reconkit ... > out.txt) the codes would show up as
# garbage. NO_COLOR is a widely used convention for users to switch colours off.
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

_CODES = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "bold": "1", "dim": "2",
}

SEVERITY_COLORS = {
    "critical": "magenta", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim",
}


def color(text: str, name: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{_CODES[name]}m{text}\033[0m"


def heading(text: str) -> None:
    line = "=" * min(78, max(len(text), 40))
    print()
    print(color(line, "blue"))
    print(color(text, "bold"))
    print(color(line, "blue"))


def info(text: str) -> None:
    print(color("[*] ", "blue") + text)


def warn(text: str) -> None:
    print(color("[!] ", "yellow") + text)


def error(text: str) -> None:
    print(color("[x] ", "red") + text, file=sys.stderr)


def wrap(text: str, indent: str = "    ") -> str:
    """Wrap long explanations so they are readable in an 80-column terminal."""
    paragraphs = text.strip().split("\n")
    return "\n".join(
        textwrap.fill(p, width=80, initial_indent=indent, subsequent_indent=indent) if p.strip() else ""
        for p in paragraphs
    )


# --- Findings ----------------------------------------------------------------

def print_finding(f: Finding) -> None:
    sev = color(f"[{f.severity.upper()}]", SEVERITY_COLORS.get(f.severity, "dim"))
    print(f"\n{sev} {color(f.title, 'bold')}")
    if f.evidence:
        print(color("  Evidence:", "dim"))
        print(wrap(f.evidence))
    print(color("  What this means:", "green"))
    print(wrap(f.what_it_means))
    print(color("  Why it matters:", "yellow"))
    print(wrap(f.why_it_matters))
    print(color("  Suggested next step:", "cyan"))
    print(wrap(f.next_step))
    for ref in f.references:
        print(color(f"    Learn more: {ref}", "dim"))


def print_module_result(result: ModuleResult) -> None:
    """The heart of reconkit: the 'What this means' section for one module."""
    heading(f"What this means: {result.module}")
    if not result.ran:
        warn(f"Module did not run: {result.note}")
        return
    if result.note:
        info(result.note)
    if not result.findings:
        info("No findings to explain. (No news is not proof of safety - "
             "it only means this tool did not spot anything.)")
        return
    counts = count_by_severity(result.findings)
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    info(f"{len(result.findings)} finding(s): {summary}")
    for f in sort_findings(result.findings):
        print_finding(f)


# --- Result folders -----------------------------------------------------------

def safe_name(text: str) -> str:
    """Make a string safe to use as a folder name.

    WHY: the target comes from the user. Characters like '/' or '..' in a folder
    name could write files outside the results directory ("path traversal").
    We replace anything that is not a letter, digit, dot, dash or underscore.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", text).strip("._")
    return cleaned or "target"


def make_results_dir(base: Path, target_host: str) -> Path:
    """Create <base>/<target>/<YYYYmmdd-HHMMSS>/ and return it.

    A new timestamped folder per run means scans never overwrite each other, so
    you can compare "before the fix" with "after the fix".
    """
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = base / safe_name(target_host) / stamp
    path.mkdir(parents=True, exist_ok=True)
    return path
