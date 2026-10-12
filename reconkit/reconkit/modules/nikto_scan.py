"""nikto: a classic web server scanner.

Nikto checks for thousands of known-dangerous files, outdated server software,
and common misconfigurations. It is LOUD (thousands of requests, an obvious
User-Agent) - it will show up in any web server log or intrusion detection
system. That's fine for authorized assessments, and a good lesson in why
attackers prefer quieter techniques.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from reconkit import tooling
from reconkit.findings import Finding, ModuleResult
from reconkit.modules.base import run_command
from reconkit.target import Target

NAME = "nikto"
TOOL = "nikto"

# Nikto messages are free text, so we recognise common ones by keyword.
# (pattern, severity, title, what, why, next)
RULES = [
    (r"x-frame-options", "low", "Clickjacking protection header missing",
     "The page doesn't tell browsers to refuse being framed by other sites.",
     "Attackers can overlay your page invisibly and trick users into clicking things.",
     "Add X-Frame-Options: DENY or CSP frame-ancestors 'self'."),
    (r"x-content-type-options", "low", "X-Content-Type-Options header missing",
     "Browsers may 'sniff' and reinterpret file types.",
     "Can let uploaded files be executed as scripts.", "Add X-Content-Type-Options: nosniff."),
    (r"strict-transport-security", "medium", "HSTS header missing",
     "Browsers aren't told to insist on HTTPS.", "Allows SSL-stripping attacks on the first visit.",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    (r"appears to be outdated|is outdated", "medium", "Outdated server software",
     "Nikto compared the version the server announced with the latest release it knows of.",
     "Outdated software is the #1 way systems get compromised: its vulnerabilities are public.",
     "Confirm the real version (vendors sometimes backport fixes without changing the number - "
     "Ubuntu/RHEL do this) and patch/upgrade."),
    (r"\btrace\b", "medium", "HTTP TRACE method enabled",
     "TRACE echoes the request back to the sender, a debugging feature.",
     "Combined with other bugs it enables Cross-Site Tracing (stealing cookies).",
     "Disable TRACE (Apache: TraceEnable off)."),
    (r"directory indexing|directory listing", "medium", "Directory listing enabled",
     "The server shows a file list when a folder has no index page.",
     "Exposes backups, config files and source code that were never meant to be linked.",
     "Disable autoindex/Options Indexes in the web server config."),
    (r"phpinfo", "high", "phpinfo() page exposed",
     "A page dumps PHP's entire configuration.",
     "Reveals paths, versions, environment variables and sometimes secrets.", "Delete the file."),
    (r"default (file|page|account|password)|installation page", "medium", "Default content found",
     "Files that ship with the software by default are still present.",
     "Default files reveal versions and sometimes include sample scripts with known vulnerabilities.",
     "Remove default/sample content from production servers."),
    (r"httponly", "low", "Cookie without HttpOnly flag",
     "A cookie can be read by JavaScript.", "If the site has an XSS bug, session cookies can be stolen.",
     "Set the HttpOnly attribute on session cookies."),
    (r"inode", "low", "ETag leaks inode numbers",
     "The ETag header includes filesystem inode numbers (an old Apache default).",
     "Minor information disclosure (CVE-2003-1418).", "Apache: FileETag MTime Size."),
    (r"(admin|login|manager|phpmyadmin|console)", "medium", "Administrative interface found",
     "Nikto found what looks like an admin or login page.",
     "Admin panels are prime targets for password guessing and often have their own vulnerabilities.",
     "Restrict admin interfaces to internal networks/VPN and require strong auth with MFA."),
    (r"(\.bak|\.old|\.sql|\.zip|\.tar|backup|\.git|\.env)", "high", "Sensitive or backup file exposed",
     "A file that looks like a backup, archive or configuration is downloadable.",
     "These frequently contain source code, database dumps or passwords.",
     "Remove the file from the web root and check whether its contents (e.g. passwords) need rotating."),
    (r"x-powered-by|server leaks|server banner", "low", "Server version disclosure",
     "The server reveals what software/version it runs.",
     "Helps attackers pick matching exploits.", "Hide version banners and keep the software patched."),
]


def build_command(binary: str, target: Target, out_path: Path) -> list[str]:
    host = target.url() if target.scheme else target.host
    return [
        binary,
        "-h", host,
        "-Format", "json",
        "-output", str(out_path),
        "-ask", "no",           # don't prompt to submit updates
        "-nointeractive",       # no keyboard interaction mid-scan
        "-maxtime", "900s",     # hard stop after 15 minutes
    ]


def load_nikto_json(text: str):
    """Parse nikto's JSON. Some nikto versions write slightly invalid JSON
    (a trailing comma before ] or }), so if strict parsing fails we remove those
    commas and try again. Being tolerant of other tools' quirks is a normal part
    of writing integrations."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(re.sub(r",\s*([\]}])", r"\1", text))


def explain_nikto(data, module: str = NAME) -> list[Finding]:
    hosts = data if isinstance(data, list) else [data]
    findings = []
    for h in hosts:
        if not isinstance(h, dict):
            continue
        where = f"{h.get('host', '')}:{h.get('port', '')}"
        if h.get("banner"):
            findings.append(Finding(
                module, f"Web server identifies itself as: {h['banner']}", "info",
                "This is the 'Server' banner nikto saw.",
                "Version banners help attackers choose exploits.",
                "Check this version is supported and patched; consider hiding the banner.",
                evidence=where))
        for v in h.get("vulnerabilities", []) or []:
            msg = (v.get("msg") or "").strip()
            evidence = f"{v.get('method', 'GET')} {v.get('url', '')}  [nikto id {v.get('id', '?')}] {msg}"
            for pattern, sev, title, what, why, nxt in RULES:
                if re.search(pattern, msg, re.IGNORECASE):
                    findings.append(Finding(module, title, sev, what, why, nxt, evidence=evidence))
                    break
            else:  # for/else: runs only if the loop did NOT `break`, i.e. no rule matched
                findings.append(Finding(
                    module, msg[:90] or "Nikto observation", "low",
                    f"Nikto reported: \"{msg}\"",
                    "Nikto flags things that are often - not always - security relevant. Many are "
                    "informational or false positives.",
                    "Visit the URL (if authorized) and decide whether it should be public. Search the "
                    "message text online to learn more.",
                    evidence=evidence))
    return findings


def run(target: Target, outdir: Path, options) -> ModuleResult:
    binary = tooling.find_tool(TOOL)
    if not binary:
        return ModuleResult(NAME, ran=False, note="nikto is not installed.")
    out = outdir / "nikto.json"
    cmd = build_command(binary, target, out)
    res = run_command(cmd, outdir, "nikto", timeout=getattr(options, "timeout", 1200))
    result = ModuleResult(NAME, ran=True, command=" ".join(cmd), raw_files=[str(out)])
    if not out.exists() or out.stat().st_size == 0:
        result.ran = False
        result.note = f"nikto produced no JSON output (exit code {res.returncode}). See nikto.log."
        return result
    try:
        data = load_nikto_json(out.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        result.ran = False
        result.note = f"Could not parse nikto's JSON output: {exc}"
        return result
    result.findings = explain_nikto(data)
    return result
