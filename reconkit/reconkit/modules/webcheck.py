"""Pure-Python web + TLS checks (always available; also the fallback for
nikto, nuclei and testssl.sh when they aren't installed).

Two halves:
  1. TLS  - connect with Python's `ssl` module and inspect the protocol
            version, cipher and certificate.
  2. HTTP - fetch the page with `requests` and inspect the response HEADERS.
            Headers are instructions the server gives the browser, and several
            exist purely to switch on browser security features.
"""

from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from reconkit import output
from reconkit.findings import Finding, ModuleResult
from reconkit.target import Target

NAME = "webcheck"
TOOL = None
USER_AGENT = "reconkit/0.1 (learning scanner; authorized testing)"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"

# (header, severity if missing, what it does, why it matters, how to fix, only-on-https?)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "medium",
     "HSTS tells browsers: 'only ever talk to me over HTTPS, for the next N seconds'.",
     "Without it, the first visit can be made over plain HTTP, and an attacker on the same "
     "network (e.g. public Wi-Fi) can intercept it and strip the encryption (an 'SSL "
     "stripping' attack).",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", True),
    ("Content-Security-Policy", "low",
     "CSP is an allow-list of where scripts, styles and images may be loaded from.",
     "It is the strongest browser-side defence against Cross-Site Scripting (XSS): even if an "
     "attacker injects a <script>, the browser refuses to run it.",
     "Start with a report-only policy (Content-Security-Policy-Report-Only) to see what would "
     "break, then enforce. https://csp-evaluator.withgoogle.com helps.", False),
    ("X-Frame-Options", "low",
     "Controls whether other websites may show this page inside a frame.",
     "Without it (or CSP frame-ancestors), an attacker can load your page invisibly inside "
     "theirs and trick users into clicking buttons ('clickjacking').",
     "Add: X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.", False),
    ("X-Content-Type-Options", "low",
     "With the value 'nosniff', stops browsers guessing a file's type.",
     "Browsers that 'sniff' content can be tricked into running an uploaded text file as "
     "JavaScript.",
     "Add: X-Content-Type-Options: nosniff", False),
    ("Referrer-Policy", "info",
     "Controls how much of the current URL is sent to other sites when users click links.",
     "URLs sometimes contain sensitive data (tokens, search terms, IDs) that would leak to "
     "third parties.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin", False),
    ("Permissions-Policy", "info",
     "Turns off powerful browser features (camera, microphone, geolocation) the site doesn't use.",
     "Limits the damage if malicious script ever runs on the page.",
     "Add e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()", False),
]

# Headers that advertise software and versions ("information disclosure").
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]

WEAK_CIPHER_WORDS = ["RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "anon"]


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def check_tls(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Return facts about the TLS service. Never raises for network problems."""
    facts: dict = {"host": host, "port": port, "reachable": False}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        facts["error"] = f"Could not connect to {host}:{port} ({exc})"
        return facts
    facts["reachable"] = True

    # create_default_context() = sensible modern settings AND certificate checking,
    # exactly like a browser. This is how you should always use ssl in real code.
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            facts.update(_session_facts(tls))
            facts["cert_verified"] = True
            cert = tls.getpeercert()
            facts["cert"] = _cert_facts(cert)
    except ssl.SSLCertVerificationError as exc:
        facts["cert_verified"] = False
        facts["cert_error"] = exc.verify_message or str(exc)
        # Connect again WITHOUT verification only so we can still report the protocol
        # and cipher. Never disable verification in code that sends real data!
        facts.update(_unverified_session(host, port, timeout))
    except (ssl.SSLError, OSError) as exc:
        facts["tls_error"] = str(exc)
        sock.close()
        return facts

    facts["legacy_protocols"] = {
        name: _accepts_protocol(host, port, version, timeout)
        for name, version in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1))
    }
    return facts


def _session_facts(tls: ssl.SSLSocket) -> dict:
    cipher = tls.cipher() or ("", "", 0)
    return {"protocol": tls.version(), "cipher": cipher[0], "cipher_bits": cipher[2]}


def _cert_facts(cert: dict) -> dict:
    def flat(rdns):  # the cert stores names as nested tuples; flatten to a dict
        return {k: v for rdn in rdns for (k, v) in rdn}
    not_after = cert.get("notAfter")
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc) if not_after else None
    return {
        "subject": flat(cert.get("subject", ())),
        "issuer": flat(cert.get("issuer", ())),
        "not_after": expires.isoformat() if expires else None,
        "days_left": (expires - datetime.now(timezone.utc)).days if expires else None,
        "san": [v for (_, v) in cert.get("subjectAltName", ())],
    }


def _unverified_session(host: str, port: int, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, \
                ctx.wrap_socket(s, server_hostname=host) as tls:
            return _session_facts(tls)
    except (ssl.SSLError, OSError):
        return {}


def _accepts_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> Optional[bool]:
    """True = server accepted this old protocol. False = refused. None = couldn't test.

    Caveat you should know: modern OpenSSL builds often refuse to even OFFER
    TLS 1.0/1.1, so a failure here might be OUR side saying no. testssl.sh ships
    its own OpenSSL for exactly this reason and gives a definitive answer.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")  # allow old ciphers so the test is fair
        except ssl.SSLError:
            pass
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, \
                ctx.wrap_socket(s, server_hostname=host):
            return True
    except ssl.SSLError as exc:
        if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() or "NO_CIPHERS" in str(exc).upper():
            return None   # our local OpenSSL refused - inconclusive
        return False
    except OSError:
        return None


def explain_tls(facts: dict, module: str = NAME) -> list[Finding]:
    f: list[Finding] = []
    host, port = facts["host"], facts["port"]
    if not facts.get("reachable"):
        f.append(Finding(
            module, f"No HTTPS service on {host}:{port}", "info",
            "Nothing accepted a connection on the HTTPS port, so there's no TLS to check.",
            "If this host serves a website, it is probably only available over unencrypted "
            "HTTP (see the HTTP findings below).",
            "If it's a website, enable HTTPS (free certificates: https://letsencrypt.org).",
            evidence=facts.get("error", "")))
        return f
    if facts.get("tls_error"):
        f.append(Finding(
            module, f"Port {port} is open but a TLS handshake failed", "info",
            "Something is listening, but it didn't complete a TLS 'handshake' (the opening "
            "negotiation where client and server agree on encryption).",
            "It may not be a TLS service at all, or it only supports settings too old for "
            "Python to negotiate.",
            "Run testssl.sh against it for a detailed answer.", evidence=facts["tls_error"]))
        return f

    proto, cipher = facts.get("protocol") or "?", facts.get("cipher") or "?"
    good = proto in ("TLSv1.3", "TLSv1.2")
    f.append(Finding(
        module, f"HTTPS negotiated {proto} with cipher {cipher}", "info" if good else "high",
        f"When Python connected, client and server agreed on protocol {proto} and the cipher "
        f"suite {cipher}. A cipher suite is the recipe of algorithms used: key exchange, "
        "encryption, and integrity checking.",
        "TLS 1.2 and 1.3 are the current safe versions. TLS 1.3 removed every known-weak "
        "option, so a 1.3 connection is a good sign." if good else
        "Older protocols have known attacks and are banned by most compliance standards.",
        "Nothing to do." if good else "Enable TLS 1.2/1.3 and disable older versions.",
        evidence=f"protocol={proto} cipher={cipher} bits={facts.get('cipher_bits')}"))

    if any(w.upper() in cipher.upper() for w in WEAK_CIPHER_WORDS):
        f.append(Finding(
            module, f"Weak cipher negotiated: {cipher}", "high",
            "The encryption algorithm chosen is outdated.",
            "Weak ciphers (RC4, 3DES, export-grade, NULL) can be broken or let an attacker "
            "decrypt captured traffic.",
            "Remove weak ciphers from the server's TLS configuration. Mozilla's SSL Configuration "
            "Generator gives safe settings: https://ssl-config.mozilla.org", evidence=cipher))

    for name, accepted in (facts.get("legacy_protocols") or {}).items():
        if accepted:
            f.append(Finding(
                module, f"Server still accepts {name}", "medium",
                f"{name} is an old version of the TLS protocol, officially deprecated in 2021 (RFC 8996).",
                "Old TLS versions are vulnerable to attacks like BEAST and POODLE-style downgrades, "
                "and fail compliance checks (PCI DSS, NIST SP 800-52r2 requires TLS 1.2+ for "
                "government systems).",
                f"Disable {name} in the web server / load balancer configuration.",
                references=["https://www.rfc-editor.org/rfc/rfc8996"]))

    if facts.get("cert_verified") is False:
        f.append(Finding(
            module, "The certificate is NOT trusted", "high",
            "Python, like a browser, checked the certificate and rejected it.",
            "Users will see a scary warning and may learn to click through warnings - which is "
            "exactly what an attacker doing a man-in-the-middle needs. Common causes: expired, "
            "self-signed, wrong hostname, or missing intermediate certificate.",
            "Read the error in the evidence, then fix the certificate (e.g. renew it, or install "
            "the full chain).",
            evidence=facts.get("cert_error", "")))
    cert = facts.get("cert") or {}
    days = cert.get("days_left")
    if days is not None:
        issuer = cert.get("issuer", {}).get("organizationName") or cert.get("issuer", {}).get("commonName", "?")
        if days < 0:
            sev, title = "critical", f"Certificate EXPIRED {-days} day(s) ago"
        elif days < 14:
            sev, title = "high", f"Certificate expires in {days} day(s)"
        elif days < 30:
            sev, title = "medium", f"Certificate expires in {days} day(s)"
        else:
            sev, title = "info", f"Certificate is valid for {days} more day(s)"
        f.append(Finding(
            module, title, sev,
            f"The certificate proves the server's identity. It was issued by '{issuer}' and is "
            f"valid until {cert.get('not_after')}.",
            "Expired certificates break the site for users and are one of the most common "
            "causes of outages. Automating renewal prevents this.",
            "Nothing to do now - but check renewal is automated." if sev == "info"
            else "Renew the certificate now and set up automatic renewal/monitoring.",
            evidence=f"subject={cert.get('subject')} SANs={', '.join(cert.get('san', [])[:5])}"))
    return f


# ---------------------------------------------------------------------------
# HTTP headers
# ---------------------------------------------------------------------------

def fetch(url: str, timeout: float = 10.0, verify: bool = True) -> Optional[requests.Response]:
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True, verify=verify,
                            headers={"User-Agent": USER_AGENT})
    except requests.exceptions.SSLError:
        if verify:
            # Cert problems are reported by the TLS check; still look at the headers.
            # (verify=False is acceptable ONLY because we send nothing sensitive.)
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
            return fetch(url, timeout, verify=False)
        return None
    except requests.RequestException:
        return None


def explain_http(http_resp: Optional[requests.Response], https_resp: Optional[requests.Response],
                 module: str = NAME) -> list[Finding]:
    f: list[Finding] = []
    if http_resp is None and https_resp is None:
        f.append(Finding(
            module, "No web server answered on HTTP or HTTPS", "info",
            "reconkit tried http:// and https:// and got no response.",
            "Nothing to assess on the web side.",
            "If you expected a website, check the hostname, port and any firewall."))
        return f

    # --- Does plain HTTP push users to HTTPS? ---
    if http_resp is not None:
        final = http_resp.url
        if final.startswith("https://"):
            f.append(Finding(
                module, "HTTP redirects to HTTPS", "info",
                "Visiting the http:// address automatically sends you to the encrypted https:// version.",
                "Good: users who type the address without https:// still end up encrypted.",
                "Nothing to do. Pair this with an HSTS header for full protection.",
                evidence=f"http -> {final}"))
        elif https_resp is not None:
            f.append(Finding(
                module, "HTTP does not redirect to HTTPS", "low",
                "The site works over HTTPS, but the plain http:// address serves content too.",
                "Users (and links) that use http:// get an unencrypted connection that can be read "
                "or altered in transit.",
                "Configure a permanent redirect (301) from http:// to https://.",
                evidence=f"http final URL: {final} (status {http_resp.status_code})"))
        else:
            f.append(Finding(
                module, "Website is only available over unencrypted HTTP", "medium",
                "There is no working HTTPS version of this site.",
                "Everything sent between users and the site - including any logins or form data "
                "- travels in cleartext. Browsers mark such sites 'Not secure'.",
                "Enable HTTPS (free certificates from Let's Encrypt) and redirect HTTP to it.",
                evidence=f"status {http_resp.status_code} at {final}"))

    resp = https_resp if https_resp is not None else http_resp
    is_https = resp.url.startswith("https://")
    headers = resp.headers  # requests gives us a case-insensitive dictionary

    for name, sev, what, why, fix, https_only in SECURITY_HEADERS:
        if https_only and not is_https:
            continue
        if name == "X-Frame-Options" and "frame-ancestors" in headers.get("Content-Security-Policy", ""):
            continue  # CSP frame-ancestors does the same job
        if name not in headers:
            f.append(Finding(module, f"Missing security header: {name}", sev, what, why, fix,
                             evidence=f"Not present in the response from {resp.url}",
                             references=[MDN + name]))

    for name in DISCLOSURE_HEADERS:
        value = headers.get(name)
        if value and any(ch.isdigit() for ch in value):
            f.append(Finding(
                module, f"{name} header reveals software version: {value}", "low",
                f"The server announces exactly what software it runs ('{value}').",
                "This is 'information disclosure'. It doesn't break anything by itself, but it "
                "saves an attacker time: they can look up vulnerabilities for that exact version.",
                f"Hide or genericise the {name} header (e.g. Apache: ServerTokens Prod; nginx: "
                "server_tokens off;). And more importantly, make sure that version is patched.",
                evidence=f"{name}: {value}"))

    for r in [*resp.history, resp]:
        for cookie in _set_cookie_headers(r):
            f.extend(_check_cookie(module, cookie, r.url.startswith("https://")))
    return f


def _set_cookie_headers(resp: requests.Response) -> list[str]:
    raw = getattr(resp, "raw", None)
    if raw is not None and hasattr(raw, "headers") and hasattr(raw.headers, "getlist"):
        return raw.headers.getlist("Set-Cookie")
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []


def _check_cookie(module: str, cookie: str, https: bool) -> list[Finding]:
    name = cookie.split("=", 1)[0].strip()
    attrs = [a.strip().lower() for a in cookie.split(";")[1:]]
    missing = []
    if https and "secure" not in attrs:
        missing.append("Secure (only send over HTTPS)")
    if "httponly" not in attrs:
        missing.append("HttpOnly (JavaScript can't read it)")
    if not any(a.startswith("samesite") for a in attrs):
        missing.append("SameSite (not sent on cross-site requests)")
    if not missing:
        return []
    return [Finding(
        module, f"Cookie '{name}' is missing protective flags", "low",
        "Cookies often hold session IDs - the thing that keeps you logged in. Flags tell the "
        "browser how carefully to guard them. Missing: " + "; ".join(missing) + ".",
        "A stolen session cookie lets an attacker become the user without a password. HttpOnly "
        "blocks theft via XSS, Secure blocks theft over unencrypted connections, SameSite "
        "helps block Cross-Site Request Forgery (CSRF).",
        "Set the missing attributes where the application creates this cookie. (Not every "
        "cookie is sensitive - focus on session/auth cookies first.)",
        evidence=cookie[:200])]


# ---------------------------------------------------------------------------

def run(target: Target, outdir: Path, options, tls_only: bool = False, http_only: bool = False) -> ModuleResult:
    findings: list[Finding] = []
    raw: dict = {}
    tls_port = target.port if (target.port and target.scheme == "https") else 443

    tls = None
    if not http_only:
        output.info(f"Checking TLS on {target.host}:{tls_port} with Python's ssl module...")
        tls = check_tls(target.host, tls_port)
        raw["tls"] = tls
        findings += explain_tls(tls)

    if not tls_only:
        output.info("Fetching the site over http:// and https:// to inspect headers...")
        http_resp = fetch(target.url("http")) if target.scheme != "https" else None
        https_resp = None
        if tls is None or tls.get("reachable") or target.scheme == "https":
            https_resp = fetch(target.url("https"))
        raw["http"] = _resp_summary(http_resp)
        raw["https"] = _resp_summary(https_resp)
        findings += explain_http(http_resp, https_resp)

    path = outdir / "webcheck.json"
    path.write_text(json.dumps(raw, indent=2, default=str), encoding="utf-8")
    return ModuleResult(NAME, ran=True, findings=findings, raw_files=[str(path)],
                        command="python requests + ssl checks")


def _resp_summary(r: Optional[requests.Response]) -> Optional[dict]:
    if r is None:
        return None
    return {"url": r.url, "status": r.status_code, "headers": dict(r.headers),
            "redirects": [h.url for h in r.history]}
