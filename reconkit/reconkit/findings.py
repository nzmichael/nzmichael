"""The shared data model every module returns.

WHY THIS FILE EXISTS:
nmap speaks XML, nuclei speaks JSON Lines, nikto speaks JSON, testssl.sh has its
own JSON layout. If the rest of the program had to understand all four formats,
it would be a mess. Instead, every module translates its tool's output into the
same simple `Finding` object. The printer and the report writer then only need
to understand one thing. This idea is called a "common data model" and you will
see it in almost every security platform (SIEMs, vulnerability scanners, etc.).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

# Ordered from most to least serious. We use the list position to sort findings
# so the scariest things are always shown first.
SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Each tool has its own words for severity. We map them all onto our five levels.
_SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "fatal": "critical",
    "high": "high",
    "medium": "medium", "moderate": "medium", "warn": "medium",
    "low": "low",
    "info": "info", "informational": "info", "ok": "info", "unknown": "info",
}


def normalize_severity(raw: Optional[str]) -> str:
    """Turn a tool-specific severity word into one of our five levels."""
    if not raw:
        return "info"
    return _SEVERITY_ALIASES.get(str(raw).strip().lower(), "info")


# A dataclass is a class that mostly just holds data. Python writes the
# __init__ and __repr__ methods for us, so the definition stays short.
@dataclass
class Finding:
    module: str            # which module produced it, e.g. "nmap"
    title: str             # one-line summary
    severity: str          # one of SEVERITIES
    what_it_means: str     # plain-English explanation
    why_it_matters: str    # the risk, i.e. what an attacker could do
    next_step: str         # what YOU should do about it
    evidence: str = ""     # the raw detail from the tool that backs this up
    references: list[str] = field(default_factory=list)  # links to learn more

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ModuleResult:
    """Everything one module produced during one run."""
    module: str
    ran: bool                         # False if skipped (tool missing, error...)
    findings: list[Finding] = field(default_factory=list)
    command: str = ""                 # the exact command we ran (so you can learn it)
    raw_files: list[str] = field(default_factory=list)  # tool output files we saved
    note: str = ""                    # why it was skipped, or other context

    def to_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first. Unknown severities sink to the bottom."""
    def rank(f: Finding) -> int:
        return SEVERITIES.index(f.severity) if f.severity in SEVERITIES else len(SEVERITIES)
    return sorted(findings, key=rank)


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
