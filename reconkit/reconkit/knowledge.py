"""Plain-English knowledge about common ports and services.

This is reconkit's "brain": a lookup table from port number to an explanation.
It is deliberately just data (a dictionary), so you can read it like a study
guide and add your own entries as you learn. Severity here is a rough starting
point for an INTERNET-FACING host; context changes everything (an open database
port on an isolated lab network is very different from one on the internet).
"""

from __future__ import annotations

from typing import Optional


def _entry(name, severity, what, why, nxt):
    return {"name": name, "severity": severity, "what": what, "why": why, "next": nxt}


PORTS: dict[int, dict] = {
    21: _entry("FTP (file transfer)", "medium",
               "FTP is an old protocol for uploading and downloading files.",
               "FTP sends usernames, passwords and files in CLEARTEXT - anyone on the network path "
               "can read them. Some servers also allow 'anonymous' login.",
               "Replace with SFTP or HTTPS uploads. If FTP must stay, restrict it by firewall and "
               "disable anonymous access."),
    22: _entry("SSH (remote administration)", "low",
               "SSH lets administrators log in to a command line remotely. Traffic is encrypted.",
               "SSH is secure by design, but internet-facing SSH is constantly hit by password-"
               "guessing bots, and outdated SSH software can have known vulnerabilities.",
               "Make sure password login is disabled in favour of SSH keys (PasswordAuthentication no), "
               "root login is disabled, and the software is patched. Consider allowing it only from "
               "a VPN or admin network."),
    23: _entry("Telnet (remote administration, unencrypted)", "high",
               "Telnet is the 1970s predecessor of SSH.",
               "Everything, including passwords, is sent in cleartext. Telnet on network devices "
               "and IoT is a classic way attackers get in (the Mirai botnet spread this way).",
               "Disable Telnet and use SSH instead. This is almost always a quick, high-value fix."),
    25: _entry("SMTP (email delivery)", "low",
               "SMTP is how mail servers send email to each other.",
               "Expected on mail servers. A misconfigured 'open relay' lets spammers send mail "
               "through you, and old versions may be vulnerable.",
               "Confirm this host is meant to be a mail server and that relaying is restricted."),
    53: _entry("DNS (name resolution)", "low",
               "DNS translates names like example.com into IP addresses.",
               "Expected on DNS servers. An 'open resolver' answering anyone on the internet can be "
               "abused in DDoS amplification attacks, and zone transfers can leak internal names.",
               "Confirm this is a DNS server, that recursion is limited to your own users, and "
               "that zone transfers (AXFR) are restricted."),
    80: _entry("HTTP (web, unencrypted)", "info",
               "A web server is answering over plain HTTP.",
               "Plain HTTP is not encrypted. That's fine if it only redirects visitors to HTTPS, "
               "but any real content or logins over HTTP can be read or modified in transit.",
               "Check that http:// redirects to https:// (run `reconkit webcheck` on this target). "
               "Then look at the web application itself with nikto/nuclei."),
    110: _entry("POP3 (email retrieval)", "medium",
                "POP3 lets email clients download mail.",
                "Unencrypted POP3 sends passwords in cleartext.",
                "Use POP3S (port 995) or IMAPS (993) instead, and disable plain POP3."),
    135: _entry("Microsoft RPC", "high",
                "Windows Remote Procedure Call endpoint mapper.",
                "Should never be reachable from the internet; historically abused by worms "
                "such as Blaster.",
                "Block it at the firewall for anything outside the internal network."),
    139: _entry("NetBIOS / SMB (Windows file sharing, legacy)", "high",
                "Older transport for Windows file and printer sharing.",
                "Windows file sharing exposed beyond the internal network leaks information and "
                "has a long history of critical, wormable vulnerabilities.",
                "Block from the internet; disable NetBIOS over TCP/IP where not needed."),
    143: _entry("IMAP (email retrieval)", "medium",
                "IMAP lets email clients read mail on the server.",
                "Unencrypted IMAP sends passwords in cleartext.",
                "Use IMAPS (port 993) and disable plain IMAP, or require STARTTLS."),
    443: _entry("HTTPS (web, encrypted)", "info",
                "A web server is answering over HTTPS (HTTP inside TLS encryption).",
                "This is normal. Its security depends on the TLS configuration and the web "
                "application behind it.",
                "Check the TLS setup with `reconkit testssl` and the web app with nikto/nuclei."),
    445: _entry("SMB (Windows file sharing)", "critical",
                "Microsoft's file-sharing protocol.",
                "SMB exposed to the internet is one of the most dangerous findings there is: "
                "WannaCry and NotPetya spread through SMB (EternalBlue, MS17-010).",
                "Block TCP 445 at the network edge immediately and confirm the host is patched."),
    1433: _entry("Microsoft SQL Server (database)", "high",
                 "A database server is directly reachable.",
                 "Databases should sit behind the application, never directly on the network edge. "
                 "Exposed databases are brute-forced and are a common cause of data breaches.",
                 "Restrict access to the application servers that need it (firewall / security group)."),
    3306: _entry("MySQL / MariaDB (database)", "high",
                 "A database server is directly reachable.",
                 "Exposed databases are routinely brute-forced and a common cause of data breaches.",
                 "Bind it to localhost or a private network, and firewall it off."),
    3389: _entry("RDP (Windows Remote Desktop)", "high",
                 "Remote Desktop gives a full graphical login to a Windows machine.",
                 "Internet-facing RDP is one of the top ways ransomware gangs get in: password "
                 "guessing, stolen credentials, and bugs like BlueKeep (CVE-2019-0708).",
                 "Put RDP behind a VPN or gateway with MFA; never expose it directly."),
    5432: _entry("PostgreSQL (database)", "high",
                 "A database server is directly reachable.",
                 "Exposed databases are routinely brute-forced and a common cause of data breaches.",
                 "Restrict with firewall rules and pg_hba.conf to only the hosts that need it."),
    5900: _entry("VNC (remote desktop)", "high",
                 "VNC shares a graphical desktop remotely.",
                 "VNC often has weak or no authentication and is frequently unencrypted.",
                 "Remove from the internet; tunnel it over SSH or a VPN if needed."),
    6379: _entry("Redis (in-memory database)", "critical",
                 "Redis is a fast key-value store used for caching.",
                 "By default Redis historically had NO password; exposed instances are taken over "
                 "within hours and used to plant cryptominers or SSH keys.",
                 "Bind Redis to localhost/private network, enable authentication (requirepass / ACLs)."),
    8080: _entry("HTTP alternate (often admin panels or dev servers)", "low",
                 "A second web server, frequently an application server, proxy or admin console.",
                 "Alternate ports often host things that were never meant to be public: Tomcat "
                 "managers, Jenkins, test builds.",
                 "Open it in a browser (if authorized) to see what it is, then decide if it should be exposed."),
    9200: _entry("Elasticsearch (search database)", "critical",
                 "Elasticsearch's HTTP API.",
                 "Unauthenticated Elasticsearch clusters have leaked billions of records.",
                 "Firewall it off and enable authentication (X-Pack security)."),
    27017: _entry("MongoDB (database)", "critical",
                  "A MongoDB database server.",
                  "Old MongoDB defaults allowed anyone to connect without a password; exposed "
                  "instances are routinely wiped and held for ransom.",
                  "Bind to a private network and enable authentication."),
    # scanme.nmap.org specials, so the first scan you run is fully explained.
    9929: _entry("Nping echo server", "info",
                 "A test service run by the Nmap project on scanme.nmap.org; it echoes packets "
                 "back so people can test the nping tool.",
                 "Harmless on scanme. On your own network, an unexpected echo/test service would "
                 "be worth asking about.",
                 "Nothing to do on scanme.nmap.org."),
    31337: _entry("Port 31337 ('elite' - a famous backdoor port)", "medium",
                  "31337 spells 'eleet' in hacker slang and was historically used by backdoors "
                  "such as Back Orifice. On scanme.nmap.org it's a deliberate joke/test.",
                  "On a real system, an unknown listener on 31337 should be investigated as a "
                  "possible compromise.",
                  "On your own systems: identify the owning process (lsof/netstat) and investigate."),
}

# Fallback lookup by service NAME, for services running on non-standard ports.
_SERVICE_TO_PORT = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "http": 80, "pop3": 110,
    "msrpc": 135, "netbios-ssn": 139, "imap": 143, "https": 443, "microsoft-ds": 445,
    "ms-sql-s": 1433, "mysql": 3306, "ms-wbt-server": 3389, "postgresql": 5432, "vnc": 5900,
    "redis": 6379, "mongodb": 27017,
}


def service_advice(service: str) -> Optional[dict]:
    port = _SERVICE_TO_PORT.get((service or "").lower())
    return PORTS.get(port) if port else None
