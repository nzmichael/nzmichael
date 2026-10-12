"""The --learn lessons: what each tool does, the key concepts, and what to look for.

Read these even without running anything:  reconkit <subcommand> --learn
"""

LESSONS = {
    "nmap": """
WHAT NMAP DOES
Nmap ("Network Mapper") finds out which network PORTS on a host are open, and
what software is listening on them. It's usually the very first step of any
assessment: you can't secure what you don't know is exposed.

KEY CONCEPTS
* IP address - the network address of a machine (e.g. 45.33.32.156).
* Port - a numbered "door" (0-65535) on that machine. Each network service
  listens on one: web on 80/443, SSH on 22, Remote Desktop on 3389.
* TCP handshake - SYN -> SYN-ACK -> ACK. Nmap learns a port's state from how
  the host answers its SYN:
    open      - answered SYN-ACK: something is listening.
    closed    - answered RST: reachable, but nothing listening.
    filtered  - no answer: a firewall is probably dropping the traffic.
* Service/version detection (-sV) - nmap talks to each open port and matches
  the replies against a database to guess the software and version.

WHAT TO LOOK FOR
* Every open port should have a business reason. Unexpected = investigate.
* Cleartext admin protocols (Telnet, FTP) and databases/remote desktop exposed
  to the internet are classic high-risk findings.
* Old software versions: look them up for known vulnerabilities (CVEs).

COMMAND WE RUN:  nmap -sV -T3 --reason -oX nmap.xml <target>
Safe practice target: scanme.nmap.org (explicitly allowed by the Nmap project).
""",
    "pyports": """
PURE-PYTHON PORT CHECK (fallback when nmap isn't installed)
Python opens a normal TCP connection to ~25 common ports. If the handshake
completes, the port is open; "connection refused" means closed; silence means
filtered. This is a "TCP connect scan" (like nmap -sT) without nmap's service
detection, timing control or retries. Install nmap for real results.
""",
    "nuclei": """
WHAT NUCLEI DOES
Nuclei sends crafted requests defined by TEMPLATES (small YAML files) and
checks whether the responses match known-vulnerable patterns. The community
maintains thousands of templates, many for specific CVEs.

KEY CONCEPTS
* CVE - "Common Vulnerabilities and Exposures": a public ID for one known
  vulnerability, e.g. CVE-2021-44228 (Log4Shell).
* CVSS - a 0-10 severity score. 9.0+ critical, 7.0+ high, 4.0+ medium.
* KEV - CISA's Known Exploited Vulnerabilities list: CVEs attackers are
  ACTUALLY using. US federal agencies must patch these by set deadlines
  (BOD 22-01). Check every CVE you find against it.
* False positive - the scanner says "vulnerable" but it isn't. Always verify.

WHAT TO LOOK FOR
* critical/high results first; check them against the KEV catalogue.
* "info" results map the technology stack - useful context, not bugs.

reconkit excludes templates tagged dos/intrusive/fuzz and limits the request
rate, so it's polite. It still sends a LOT of requests: authorization matters.
""",
    "nikto": """
WHAT NIKTO DOES
Nikto is a web server scanner. It requests thousands of known-risky paths
(old admin pages, backup files, default install files) and checks the
server's headers and version banners against its database.

KEY CONCEPTS
* HTTP request/response - the browser asks (GET /page), the server answers
  with a status code (200 OK, 404 Not Found, 403 Forbidden) and HEADERS.
* Misconfiguration - not a software bug, but an unsafe setting: directory
  listing on, debug pages left behind, default credentials.
* Information disclosure - the server revealing versions, paths or internals.

WHAT TO LOOK FOR
* Exposed backups (.bak, .sql, .zip, .git, .env) - often contain secrets.
* Admin interfaces reachable from outside.
* "Outdated" software - but verify, as Linux distros backport fixes.

Nikto is NOISY: thousands of requests with an obvious signature. It will
appear in logs and may trigger alerts. Warn the system owner/SOC beforehand.
""",
    "testssl": """
WHAT TESTSSL.SH DOES
testssl.sh checks how well a server's TLS (the "S" in HTTPS) is configured:
which protocol versions and ciphers it accepts, its certificate, and whether
it's vulnerable to known TLS attacks (Heartbleed, POODLE, ROBOT...).

KEY CONCEPTS
* TLS - Transport Layer Security; encrypts traffic between client and server.
  "SSL" is its outdated predecessor (the name stuck around).
* Protocol versions - SSLv2/SSLv3/TLS 1.0/1.1 are deprecated and unsafe.
  TLS 1.2 and 1.3 are the ones you want. (NIST SP 800-52r2 requires TLS 1.2+
  for US government systems.)
* Cipher suite - the combination of algorithms used for key exchange,
  encryption and integrity, e.g. ECDHE-RSA-AES256-GCM-SHA384.
* Forward secrecy - each session gets a fresh key, so a stolen server key
  can't decrypt previously recorded traffic.
* Certificate - a signed document proving the server's identity, issued by a
  Certificate Authority (CA), valid for set dates and hostnames.

WHAT TO LOOK FOR
* Any old protocol enabled, weak ciphers (RC4, 3DES, EXPORT, NULL).
* Certificate problems: expired, untrusted chain, wrong name, small key.
* Named vulnerabilities marked HIGH/CRITICAL.
""",
    "webcheck": """
WHAT WEBCHECK DOES (pure Python, no external tools)
1. Connects with TLS and reports the protocol, cipher and certificate expiry.
2. Fetches the page over http:// and https:// and reviews the HTTP headers.

KEY CONCEPTS
* Security headers - instructions telling the BROWSER to turn on protections:
  HSTS (always use HTTPS), CSP (only run approved scripts), X-Frame-Options
  (no clickjacking), X-Content-Type-Options (no type sniffing).
* Cookies & flags - session cookies keep you logged in. Secure, HttpOnly and
  SameSite flags stop them being stolen or misused.
* Redirect - http:// should send users to https:// automatically.

WHAT TO LOOK FOR
* Missing HSTS on an HTTPS site, no HTTP->HTTPS redirect.
* Version numbers in Server / X-Powered-By headers.
* Session cookies without Secure/HttpOnly.

This is a quick first look, not a replacement for nikto, nuclei or testssl.sh.
""",
}
