"""nmap: discover which ports are open and what software is listening.

Nmap can write results as XML (-oX). XML is a structured format, so we parse it
with Python's built-in xml.etree module rather than scraping the human-readable
text output - text formats change between versions, structured formats rarely do.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote_plus

from reconkit import tooling
from reconkit.findings import Finding, ModuleResult
from reconkit.knowledge import PORTS, service_advice
from reconkit.modules.base import run_command
from reconkit.target import Target

NAME = "nmap"
TOOL = "nmap"

_PORTS_RE = re.compile(r"^[0-9,\-]+$")


def build_command(binary: str, target: Target, xml_path: Path, ports: str = "", fast: bool = False) -> list[str]:
    cmd = [
        binary,
        "-sV",              # Service/Version detection: ask each open port what software it runs
        "-T3",              # Timing template 3 = "normal". Higher is faster but noisier/less reliable
        "--reason",         # record WHY nmap decided a port is open/closed (great for learning)
        "-oX", str(xml_path),  # save machine-readable XML for us to parse
    ]
    if ports:
        if not _PORTS_RE.match(ports):
            raise ValueError("Ports must look like 22,80,443 or 1-1024")
        cmd += ["-p", ports]
    elif fast:
        cmd += ["-F"]       # Fast mode: top 100 ports instead of the default top 1000
    cmd.append(target.host)
    return cmd


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Return a list of hosts, each with a list of ports. Pure function: no I/O."""
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        status_el = host.find("status")
        hostname_el = host.find("hostnames/hostname")
        ports = []
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            svc = port.find("service")
            ports.append({
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "state": state_el.get("state", "") if state_el is not None else "",
                "reason": state_el.get("reason", "") if state_el is not None else "",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
            })
        # <extraports> summarises the many ports nmap didn't list individually.
        extra = [
            {"state": e.get("state", ""), "count": int(e.get("count", 0))}
            for e in host.findall("ports/extraports")
        ]
        hosts.append({
            "address": addr_el.get("addr", "") if addr_el is not None else "",
            "hostname": hostname_el.get("name", "") if hostname_el is not None else "",
            "status": status_el.get("state", "") if status_el is not None else "",
            "ports": ports,
            "extraports": extra,
        })
    return hosts


def explain_ports(hosts: list[dict], module: str = NAME) -> list[Finding]:
    """Turn parsed port data into plain-English findings."""
    findings: list[Finding] = []
    if not hosts:
        findings.append(Finding(
            module, "Nmap reported the host as down or unreachable", "info",
            "Nmap first checks whether a host is alive (\"host discovery\", using pings and "
            "probes to common ports). It got no reply, so it didn't scan any ports.",
            "Many networks and firewalls block ping. The host may still be up.",
            "Check the target name/IP is right. If you're sure it's up, run nmap yourself "
            "with -Pn (\"skip host discovery, assume it's up\").",
        ))
        return findings

    for host in hosts:
        label = host["hostname"] or host["address"]
        open_ports = [p for p in host["ports"] if p["state"] in ("open", "open|filtered")]
        for p in open_ports:
            findings.append(_explain_open_port(module, label, p))

        filtered = sum(e["count"] for e in host["extraports"] if e["state"] == "filtered")
        filtered += sum(1 for p in host["ports"] if p["state"] == "filtered")
        closed = sum(e["count"] for e in host["extraports"] if e["state"] == "closed")
        closed += sum(1 for p in host["ports"] if p["state"] == "closed")
        if filtered or closed:
            findings.append(Finding(
                module, f"{closed} closed and {filtered} filtered port(s) on {label}", "info",
                "CLOSED means the host answered \"nothing is listening here\" (it sent a TCP "
                "reset). FILTERED means nmap got no answer at all - usually a firewall silently "
                "dropping the probe.",
                "Filtered ports are a good sign: a firewall is limiting what the outside world "
                "can reach. Closed ports are harmless but show the host is reachable.",
                "Nothing to fix. Compare this with what you EXPECT to be exposed - every open "
                "port should have a business reason.",
            ))
        if not open_ports:
            findings.append(Finding(
                module, f"No open ports found on {label}", "info",
                "Nmap didn't find any listening services in the ports it checked.",
                "A small attack surface is good, but by default nmap only checks the 1000 "
                "most common TCP ports - not all 65535, and no UDP.",
                "For a fuller picture (with permission!), try `--ports 1-65535`.",
            ))
    return findings


def _explain_open_port(module: str, label: str, p: dict) -> Finding:
    port, proto = p["port"], p["protocol"]
    software = " ".join(x for x in (p["product"], p["version"]) if x).strip()
    evidence = (f"{port}/{proto} {p['state']} (reason: {p['reason'] or 'n/a'}) "
                f"service={p['service'] or 'unknown'}"
                + (f" software={software}" if software else "")
                + (f" ({p['extrainfo']})" if p["extrainfo"] else ""))

    kb = PORTS.get(port) or service_advice(p["service"])
    if kb:
        title = f"{kb['name']} is open on {label} (port {port}/{proto})"
        severity, what, why, nxt = kb["severity"], kb["what"], kb["why"], kb["next"]
    else:
        title = f"Port {port}/{proto} is open on {label} ({p['service'] or 'unknown service'})"
        severity = "low"
        what = (f"Something is listening on port {port}. Nmap's best guess at the service is "
                f"'{p['service'] or 'unknown'}'.")
        why = ("Every open port is a door into the system. Unknown or unexpected services are "
               "worth investigating - they are often forgotten test services or misconfigurations.")
        nxt = "Find out what owns this port (ask the system owner, or run `sudo lsof -i :%d` on the host)." % port

    refs = []
    if software:
        # Teach the habit: look up the exact software version in vulnerability databases.
        nxt += (f" Then look up '{software}' for known vulnerabilities (CVEs) and check it's "
                f"still supported by the vendor.")
        refs.append("https://nvd.nist.gov/vuln/search/results?query=" + quote_plus(software))
    if p["service"] == "tcpwrapped":
        what += (" Nmap says 'tcpwrapped': the connection opened, then closed immediately "
                 "without any data. Something (a firewall or access-control wrapper) accepts "
                 "the connection but refuses to talk to you.")
    return Finding(module, title, severity, what, why, nxt, evidence=evidence, references=refs)


def run(target: Target, outdir: Path, options) -> ModuleResult:
    binary = tooling.find_tool(TOOL)
    if not binary:
        return ModuleResult(NAME, ran=False, note="nmap is not installed.")
    xml_path = outdir / "nmap.xml"
    cmd = build_command(binary, target, xml_path,
                        ports=getattr(options, "ports", "") or "",
                        fast=getattr(options, "fast", False))
    res = run_command(cmd, outdir, "nmap", timeout=getattr(options, "timeout", 900))
    result = ModuleResult(NAME, ran=True, command=" ".join(cmd), raw_files=[str(xml_path)])
    if not xml_path.exists() or xml_path.stat().st_size == 0:
        result.ran = False
        result.note = f"nmap produced no XML output (exit code {res.returncode}). See nmap.log. {res.stderr.strip()[:300]}"
        return result
    try:
        hosts = parse_nmap_xml(xml_path.read_text(encoding="utf-8", errors="replace"))
    except ET.ParseError as exc:
        # A timeout can leave half-written XML behind.
        result.ran = False
        result.note = f"Could not parse nmap's XML ({exc}). The scan may have been interrupted."
        return result
    result.findings = explain_ports(hosts)
    return result
