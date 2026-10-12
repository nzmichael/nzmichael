"""Pure-Python fallback port check (used when nmap isn't installed).

HOW IT WORKS - the "TCP connect" scan:
TCP connections start with a three-way handshake: you send SYN, the server
replies SYN-ACK if something is listening (or RST if nothing is), and you reply
ACK. socket.connect_ex() performs the whole handshake for us and returns 0 if it
succeeded (port OPEN), or an error code if refused (CLOSED) or timed out
(probably FILTERED by a firewall). This is the same as `nmap -sT`, minus nmap's
cleverness (service detection, timing, retries). It's slow and limited - that's
the point: it shows you why real tools exist.
"""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from reconkit import output
from reconkit.findings import ModuleResult
from reconkit.modules.nmap_scan import explain_ports
from reconkit.target import Target

NAME = "pyports"
TOOL = None

# A small list of commonly exposed ports. Real nmap checks 1000 by default.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 9929, 27017, 31337]

_GUESS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
          110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
          445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 3306: "mysql",
          3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
          8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"}


def check_port(host: str, port: int, timeout: float = 2.0) -> str:
    # `with` guarantees the socket is closed even if something goes wrong.
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except OSError:
        return "filtered"


def run(target: Target, outdir: Path, options) -> ModuleResult:
    ports = COMMON_PORTS
    output.info(f"Checking {len(ports)} common TCP ports on {target.host} with plain Python sockets...")
    try:
        addr = socket.gethostbyname(target.host)  # DNS lookup: name -> IP address
    except socket.gaierror:
        return ModuleResult(NAME, ran=False, note=f"Could not resolve '{target.host}' (DNS lookup failed).")

    # A few threads at once keeps it reasonably quick without hammering the target.
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = dict(zip(ports, pool.map(lambda p: check_port(addr, p), ports)))

    host = {
        "address": addr, "hostname": target.host, "status": "up",
        "ports": [{"port": p, "protocol": "tcp", "state": s, "reason": "connect",
                   "service": _GUESS.get(p, "") if s == "open" else "",
                   "product": "", "version": "", "extrainfo": ""}
                  for p, s in states.items()],
        "extraports": [],
    }
    raw = outdir / "pyports.json"
    raw.write_text(json.dumps(host, indent=2), encoding="utf-8")
    findings = explain_ports([host], module=NAME)
    return ModuleResult(
        NAME, ran=True, findings=findings, raw_files=[str(raw)],
        command=f"python socket connect() to {len(ports)} common ports",
        note=("Fallback mode: only common ports were checked and software versions were not "
              "detected. Install nmap for real results."),
    )
