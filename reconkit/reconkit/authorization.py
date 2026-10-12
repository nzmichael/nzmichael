"""The authorization gate and the audit log.

WHY THIS MATTERS:
Scanning a system you don't own or have written permission to test can be a
crime (e.g. the Computer Fraud and Abuse Act in the US, the Computer Misuse Act
in the UK, and similar laws elsewhere) and, at work, a policy violation even if
your intentions are good. In government IT security, the normal practice is a
signed authorization or "Rules of Engagement" document that lists exactly which
systems may be tested, when, and by whom.

reconkit makes you stop and confirm every time, and writes an audit record. An
audit trail answers "who scanned what, and when?" - the first question anyone
asks when a scan sets off an alarm in a security operations centre (SOC).
"""

from __future__ import annotations

import getpass
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from reconkit import output
from reconkit.target import Target

# Hosts whose owners publicly invite testing. Even here there are limits.
KNOWN_PRACTICE_TARGETS = {
    "scanme.nmap.org": (
        "The Nmap Project explicitly allows scanning scanme.nmap.org with Nmap and other "
        "port scanners for learning (see http://scanme.nmap.org/). Please be gentle: a few "
        "scans a day, no brute-forcing or denial-of-service. That permission is about PORT "
        "SCANNING - heavier web scanners (nikto, nuclei) are a grey area there. For web "
        "scanners, practise on your own lab, e.g. OWASP Juice Shop in Docker."
    ),
}

AUDIT_FILENAME = "audit.log"


def print_warning(target: Target, modules: list[str]) -> None:
    output.heading("AUTHORIZATION CHECK")
    print(output.color(
        "You are about to send network traffic designed to find weaknesses.", "bold"))
    print(output.wrap(
        "Only scan systems that you OWN, or that you have WRITTEN permission to test "
        "(for example, an approved Rules of Engagement or change ticket at work). "
        "Unauthorized scanning can be illegal and can trigger security alerts, "
        "incident response, or service disruption.", indent="  "))
    print()
    print(f"  Target:  {output.color(target.host, 'bold')}  (you typed: {target.original})")
    print(f"  Modules: {', '.join(modules)}")
    note = KNOWN_PRACTICE_TARGETS.get(target.host.lower())
    if note:
        print()
        print(output.color("  Note about this target:", "green"))
        print(output.wrap(note, indent="  "))
    print()


def confirm_authorization(
    target: Target,
    modules: list[str],
    audit_dir: Path,
    input_func: Optional[Callable[[str], str]] = None,
) -> bool:
    """Show the warning, ask for 'yes', log the answer. Returns True if confirmed.

    `input_func` is a parameter (defaulting to the built-in input) so that tests
    can pass in a fake that returns "yes" without a human at the keyboard. This
    technique is called "dependency injection". (We look up `input` at call time
    rather than writing `input_func=input` in the signature, because default
    values are evaluated once, when the function is defined.)
    """
    input_func = input_func or input
    print_warning(target, modules)
    try:
        answer = input_func('Type "yes" to confirm you own or are authorized to test this target: ')
    except EOFError:
        # EOFError happens if there is no keyboard input at all (e.g. piped input ended).
        answer = ""
    # Exactly "yes" - not "y", not Enter. A deliberate action, not a reflex.
    confirmed = answer.strip().lower() == "yes"
    write_audit(audit_dir, {
        "event": "authorization",
        "target": target.host,
        "target_as_typed": target.original,
        "modules": modules,
        "confirmed": confirmed,
        "answer": answer.strip()[:50],
    })
    if not confirmed:
        output.warn('Authorization not confirmed (you must type exactly "yes"). Nothing was scanned.')
    return confirmed


def write_audit(audit_dir: Path, record: dict) -> Path:
    """Append one JSON object per line ("JSON Lines") to the audit log.

    WHY JSON Lines: each line is a complete record, so the file can be appended
    to safely and read by log tools (Splunk, grep, jq) one line at a time.
    WHY UTC: logs from different machines/time zones can be compared directly.
    """
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / AUDIT_FILENAME
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": _safe(getpass.getuser),
        "machine": _safe(socket.gethostname),
        **record,
    }
    # "a" = append mode, so we never erase earlier audit entries.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return path


def _safe(func: Callable[[], str]) -> str:
    try:
        return func()
    except Exception:  # getuser() can fail in unusual environments; never crash the audit.
        return "unknown"
