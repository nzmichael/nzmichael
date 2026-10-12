"""`reconkit glossary` - short definitions of common security terms.

Kept alphabetical so it's easy to scan. Add your own as you learn!
"""

GLOSSARY = {
    "Attack surface": "Everything an attacker can reach and try to abuse: open ports, web pages, "
                      "APIs, user accounts. Assessments map it; hardening shrinks it.",
    "Authorization (testing)": "Written permission from the system owner to test, stating scope, dates "
                               "and methods. Without it, scanning can be illegal. Often called Rules of Engagement.",
    "Banner": "Text a service sends identifying itself, e.g. 'SSH-2.0-OpenSSH_8.9'. Banner grabbing "
              "is how tools guess software versions.",
    "Certificate (TLS)": "A file signed by a Certificate Authority proving a server owns a hostname. "
                         "Has an expiry date and a list of names (SANs) it's valid for.",
    "Cipher suite": "The set of algorithms a TLS connection uses for key exchange, encryption and "
                    "integrity, e.g. TLS_AES_256_GCM_SHA384.",
    "Cleartext": "Data sent without encryption; anyone on the network path can read it. "
                 "Telnet, FTP and HTTP are cleartext protocols.",
    "CSP": "Content-Security-Policy: an HTTP header listing which sources of scripts and content "
           "the browser may load. The main browser-side defence against XSS.",
    "CVE": "Common Vulnerabilities and Exposures: a unique public ID for a known vulnerability, "
           "e.g. CVE-2014-0160 (Heartbleed). Look them up at nvd.nist.gov.",
    "CVSS": "Common Vulnerability Scoring System: a 0-10 severity score. 0.1-3.9 low, 4.0-6.9 "
            "medium, 7.0-8.9 high, 9.0-10 critical.",
    "CSRF": "Cross-Site Request Forgery: tricking a logged-in user's browser into making an "
            "unwanted request to another site. SameSite cookies and CSRF tokens prevent it.",
    "Exploit": "Code or a technique that takes advantage of a vulnerability.",
    "False positive": "A scanner reports a problem that isn't really there. Always verify findings "
                      "before reporting them.",
    "Firewall": "A device or software that allows or blocks network traffic by rules. It's why "
                "nmap shows ports as 'filtered'.",
    "Forward secrecy": "A TLS property where each session uses a temporary key, so stealing the "
                       "server's long-term key later can't decrypt recorded past sessions.",
    "Hardening": "Reducing attack surface by disabling unneeded services and applying secure "
                 "settings, e.g. following CIS Benchmarks or DISA STIGs.",
    "HSTS": "HTTP Strict Transport Security: a header telling browsers to only use HTTPS for a site.",
    "HTTP header": "Name: value lines sent before a web page's content. Some control browser "
                   "security features; some leak information.",
    "Information disclosure": "A system revealing details (versions, paths, internal IPs) that help "
                              "an attacker, without directly being exploitable.",
    "KEV": "CISA's Known Exploited Vulnerabilities catalogue: CVEs confirmed exploited in the wild. "
           "US federal agencies must remediate them by deadlines (BOD 22-01).",
    "Man-in-the-middle (MITM)": "An attacker positioned between two parties who can read or alter "
                                "their traffic. Encryption with proper certificate checks stops it.",
    "NVD": "The US National Vulnerability Database (nvd.nist.gov): CVE details, CVSS scores and references.",
    "Patch": "A software update that fixes bugs, including security vulnerabilities.",
    "Port": "A number (0-65535) identifying a network service on a host. Well-known ones: 22 SSH, "
            "80 HTTP, 443 HTTPS, 3389 RDP.",
    "Port scan": "Checking which ports on a host accept connections. The first step of reconnaissance.",
    "Reconnaissance (recon)": "The information-gathering phase: finding hosts, ports, software and "
                              "people before trying to attack or defend.",
    "Remediation": "Fixing a vulnerability: patching, reconfiguring, removing, or adding a "
                   "compensating control.",
    "SAN": "Subject Alternative Name: the list of hostnames a TLS certificate is valid for.",
    "Severity": "How bad a finding is, usually critical/high/medium/low/info. Real risk also depends "
                "on context: exposure, data sensitivity, exploitability.",
    "SSL": "Secure Sockets Layer: the obsolete predecessor of TLS. All SSL versions are insecure.",
    "TCP handshake": "SYN, SYN-ACK, ACK - how a TCP connection starts. Port scanners read the reply "
                     "to the SYN to decide if a port is open (SYN-ACK) or closed (RST).",
    "TLS": "Transport Layer Security: encrypts network traffic (the S in HTTPS). Use TLS 1.2 or 1.3.",
    "Vulnerability": "A weakness that could be exploited to harm confidentiality, integrity or "
                     "availability of a system.",
    "Vulnerability assessment": "Systematically finding and prioritising weaknesses, usually with "
                                "scanners plus manual verification. Unlike a penetration test, it "
                                "does not try to exploit them.",
    "XSS": "Cross-Site Scripting: injecting malicious JavaScript into a page other users view, often "
           "to steal session cookies.",
}
