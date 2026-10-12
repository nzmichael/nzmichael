"""testssl.sh: a thorough TLS/SSL configuration checker.

testssl.sh tests every protocol version, every cipher, the certificate chain,
and dozens of named vulnerabilities (Heartbleed, POODLE, ROBOT...). It ships
with its own OpenSSL build so it can test OLD insecure settings that your
system's OpenSSL refuses to speak.

Its JSON output (--jsonfile) is a flat list of checks, each with an "id",
"severity" (OK, INFO, LOW, MEDIUM, HIGH, CRITICAL, WARN...) and "finding".
"""

from __future__ import annotations

import json
from pathlib import Path

from reconkit import tooling
from reconkit.findings import Finding, ModuleResult, normalize_severity
from reconkit.modules.base import run_command
from reconkit.target import Target

NAME = "testssl"
TOOL = "testssl"

# id prefix -> (friendly name, what it is, why it matters, fix)
KB = {
    "SSLv2": ("SSL 2.0", "SSL 2.0 is the 1995 ancestor of TLS.", "Completely broken (DROWN attack).",
              "Disable SSLv2 everywhere."),
    "SSLv3": ("SSL 3.0", "SSL 3.0 is the last version before TLS.", "Broken by the POODLE attack (2014).",
              "Disable SSLv3."),
    "TLS1_1": ("TLS 1.1", "TLS 1.1 (2006) is deprecated.", "Deprecated by RFC 8996; fails NIST SP 800-52r2.",
               "Disable TLS 1.1, keep 1.2 and 1.3."),
    "TLS1": ("TLS 1.0", "TLS 1.0 (1999) is deprecated.", "Vulnerable to BEAST-style attacks; fails compliance.",
             "Disable TLS 1.0, keep 1.2 and 1.3."),
    "TLS1_2": ("TLS 1.2", "TLS 1.2 (2008) is the widely supported safe baseline.",
               "Not offering TLS 1.2 would lock out many clients or mean only old versions are offered.",
               "Make sure TLS 1.2 is enabled."),
    "TLS1_3": ("TLS 1.3", "TLS 1.3 is the newest, fastest and safest TLS version.",
               "Not offering it isn't a vulnerability, but it's the modern best practice.",
               "Enable TLS 1.3 if your server software supports it."),
    "heartbleed": ("Heartbleed", "A 2014 OpenSSL bug that leaks server memory.",
                   "Attackers could read private keys and passwords straight from memory.",
                   "Upgrade OpenSSL and replace (re-key) the certificate."),
    "CCS": ("CCS injection", "An OpenSSL handshake bug (CVE-2014-0224).", "Allows man-in-the-middle decryption.",
            "Upgrade OpenSSL."),
    "ROBOT": ("ROBOT", "A 19-year-old RSA padding oracle attack, rediscovered in 2017.",
              "Can let attackers decrypt traffic or sign with the server's key.",
              "Disable RSA key-exchange ciphers (prefer ECDHE)."),
    "POODLE_SSL": ("POODLE", "Padding attack on SSLv3.", "Can decrypt cookies.", "Disable SSLv3."),
    "SWEET32": ("SWEET32", "Attack on 64-bit block ciphers like 3DES.", "Large amounts of traffic can be decrypted.",
                "Remove 3DES/IDEA ciphers."),
    "FREAK": ("FREAK", "Forces 'export-grade' (deliberately weak 1990s) RSA.", "Keys can be cracked quickly.",
              "Remove EXPORT ciphers."),
    "DROWN": ("DROWN", "Uses SSLv2 on any server sharing your key to decrypt TLS.", "Decrypts modern TLS sessions.",
              "Disable SSLv2 on every server that shares this certificate/key."),
    "LOGJAM": ("Logjam", "Downgrade to weak Diffie-Hellman groups.", "Allows decryption by well-resourced attackers.",
               "Use 2048-bit+ DH groups or ECDHE only."),
    "BEAST": ("BEAST", "Attack on CBC ciphers in TLS 1.0.", "Mostly mitigated in browsers today; signals old config.",
              "Disable TLS 1.0."),
    "LUCKY13": ("Lucky13", "Timing attack on CBC ciphers.", "Theoretical but signals CBC ciphers in use.",
                "Prefer AEAD ciphers (AES-GCM, ChaCha20)."),
    "RC4": ("RC4 ciphers", "RC4 is a broken stream cipher.", "Biases allow plaintext recovery.", "Remove RC4."),
    "CRIME_TLS": ("CRIME", "Compression-based attack on TLS.", "Can recover secret cookies.", "Disable TLS compression."),
    "BREACH": ("BREACH", "Compression attack on HTTP responses.",
               "Can recover secrets from compressed pages; often a false positive on pages without secrets.",
               "Review whether compressed responses contain secrets/CSRF tokens."),
    "secure_renego": ("Secure renegotiation", "Whether the server safely supports renegotiation.",
                      "Insecure renegotiation allows injecting data into sessions.", "Patch the TLS library."),
    "secure_client_renego": ("Client-initiated renegotiation", "Clients can ask to redo the handshake.",
                             "Can be abused for denial of service.", "Disable client-initiated renegotiation."),
    "fallback_SCSV": ("TLS_FALLBACK_SCSV", "Protection against protocol downgrade attacks.",
                      "Without it, attackers may force weaker protocols.", "Enable it (modern libraries do by default)."),
    "cipherlist_NULL": ("NULL ciphers", "Ciphers with NO encryption.", "Traffic is in cleartext.", "Remove NULL ciphers."),
    "cipherlist_aNULL": ("Anonymous ciphers", "Ciphers with no authentication.", "Trivial man-in-the-middle.",
                         "Remove aNULL ciphers."),
    "cipherlist_EXPORT": ("Export ciphers", "Deliberately weakened 1990s ciphers.", "Crackable.", "Remove EXPORT ciphers."),
    "cipherlist_LOW": ("Low-strength ciphers", "Ciphers using 64-bit or smaller keys.", "Crackable.", "Remove them."),
    "cipherlist_3DES_IDEA": ("3DES/IDEA ciphers", "64-bit block ciphers.", "Vulnerable to SWEET32.", "Remove them."),
    "cipherlist_OBSOLETED": ("Obsolete CBC ciphers", "Older CBC-mode ciphers without forward secrecy.",
                             "Weaker than modern AEAD ciphers.", "Prefer ECDHE + AES-GCM/ChaCha20."),
    "FS": ("Forward secrecy", "Forward secrecy means each session uses a fresh key.",
           "Without it, stealing the server's key later decrypts all recorded past traffic.",
           "Prefer ECDHE/DHE key exchange."),
    "HSTS": ("HSTS", "The Strict-Transport-Security header.", "Without it, SSL stripping is possible.",
             "Add Strict-Transport-Security with a long max-age."),
    "cert_expirationStatus": ("Certificate expiry", "Whether the certificate is within its validity dates.",
                              "Expired certificates break trust and the site.", "Renew and automate renewal."),
    "cert_chain_of_trust": ("Certificate chain", "Whether the cert chains to a trusted root CA.",
                            "Untrusted chains cause browser warnings and train users to ignore them.",
                            "Install the full chain (including intermediates) from a trusted CA."),
    "cert_trust": ("Certificate name match", "Whether the cert covers this hostname.",
                   "Name mismatches cause warnings and may indicate the wrong cert is installed.",
                   "Issue a certificate whose SANs include this hostname."),
    "cert_keySize": ("Certificate key size", "The size of the certificate's public key.",
                     "RSA keys under 2048 bits are considered breakable.", "Use RSA 2048+ or ECDSA P-256+."),
    "cert_signatureAlgorithm": ("Certificate signature algorithm", "How the CA signed the certificate.",
                                "SHA-1 and MD5 signatures can be forged.", "Reissue with SHA-256 or better."),
}

SKIP_SEVERITIES = {"OK", "DEBUG"}


def build_command(binary: str, target: Target, out_path: Path) -> list[str]:
    port = target.port if (target.port and target.scheme == "https") else 443
    return [
        binary,
        "--jsonfile", str(out_path),
        "--quiet",                 # no banner
        "--color", "0",
        "--warnings", "batch",     # never stop and ask questions mid-scan
        f"{target.host}:{port}",
    ]


def _lookup(check_id: str):
    # Exact match first, then longest prefix match (e.g. "cert_keySize <cert#1>").
    if check_id in KB:
        return KB[check_id]
    candidates = [k for k in KB if check_id.startswith(k)]
    return KB[max(candidates, key=len)] if candidates else None


def explain_testssl(entries: list[dict], module: str = NAME) -> list[Finding]:
    findings = []
    passed = 0
    for e in entries:
        raw_sev = str(e.get("severity", "")).upper()
        check_id = str(e.get("id", ""))
        text = str(e.get("finding", ""))
        if raw_sev in SKIP_SEVERITIES:
            passed += 1
            continue
        if raw_sev == "FATAL" or check_id in ("scanProblem", "scanTime"):
            if raw_sev == "FATAL":
                findings.append(Finding(
                    module, "testssl.sh could not complete the scan", "info",
                    "testssl.sh hit a fatal problem - most often there is no TLS service on that port.",
                    "Nothing was tested, so no conclusions can be drawn.",
                    "Check the host/port. See testssl.log for the exact error.", evidence=text))
            continue
        sev = normalize_severity(raw_sev)
        kb = _lookup(check_id)
        if sev == "info" and not kb:
            continue  # testssl emits hundreds of INFO facts; keep only the ones we can explain
        if kb:
            name, what, why, fix = kb
            title = f"{name}: {text}"[:120]
        else:
            name, what, why, fix = (check_id, f"testssl.sh check '{check_id}' reported: {text}",
                                    "testssl.sh rates this as a weakness in the TLS configuration.",
                                    "Search for the check name in the testssl.sh docs and compare with "
                                    "https://ssl-config.mozilla.org recommendations.")
            title = f"{check_id}: {text}"[:120]
        if sev == "info":
            fix = "Nothing to do - this is context."
        evidence = f"id={check_id} severity={raw_sev} finding={text}"
        refs = []
        if e.get("cve"):
            evidence += f" cve={e['cve']}"
            refs = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in str(e["cve"]).split()][:3]
        findings.append(Finding(module, title, sev, what, why, fix, evidence=evidence, references=refs))
    if passed:
        findings.append(Finding(
            module, f"{passed} TLS checks passed", "info",
            "testssl.sh rated these checks 'OK' - no problem found.",
            "Passing checks are just as informative as failures: they show what's configured well.",
            "See testssl.json for the full list."))
    return findings


def run(target: Target, outdir: Path, options) -> ModuleResult:
    binary = tooling.find_tool(TOOL)
    if not binary:
        return ModuleResult(NAME, ran=False, note="testssl.sh is not installed.")
    out = outdir / "testssl.json"
    cmd = build_command(binary, target, out)
    res = run_command(cmd, outdir, "testssl", timeout=getattr(options, "timeout", 1200))
    result = ModuleResult(NAME, ran=True, command=" ".join(cmd), raw_files=[str(out)])
    if not out.exists() or out.stat().st_size == 0:
        result.ran = False
        result.note = f"testssl.sh produced no JSON (exit code {res.returncode}). See testssl.log."
        return result
    try:
        entries = json.loads(out.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        result.ran = False
        result.note = f"Could not parse testssl.sh JSON: {exc}"
        return result
    result.findings = explain_testssl(entries if isinstance(entries, list) else entries.get("scanResult", []))
    return result
