"""Tests run without network access or any external tools installed.

Run with:  python -m pytest
Each test feeds a parser SAMPLE output (in the tool's real format) and checks
the explanation. Reading tests is also a quick way to see what each tool's raw
output looks like.
"""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from reconkit import authorization, cli
from reconkit.findings import Finding, ModuleResult
from reconkit.modules import nikto_scan, nmap_scan, nuclei_scan, testssl_scan, webcheck
from reconkit.report import write_reports
from reconkit.target import parse_target

# Trimmed real-world-shaped nmap XML for scanme.nmap.org.
NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - scanme.nmap.org">
<host><status state="up" reason="syn-ack"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
<ports><extraports state="closed" count="995"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
 <service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu 2ubuntu2.13" extrainfo="Ubuntu Linux; protocol 2.0"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
 <service name="http" product="Apache httpd" version="2.4.7" extrainfo="(Ubuntu)"/></port>
<port protocol="tcp" portid="23"><state state="open" reason="syn-ack"/><service name="telnet"/></port>
<port protocol="tcp" portid="9929"><state state="open" reason="syn-ack"/><service name="nping-echo"/></port>
<port protocol="tcp" portid="31337"><state state="open" reason="syn-ack"/><service name="tcpwrapped"/></port>
</ports></host></nmaprun>"""


# --- target validation ------------------------------------------------------

@pytest.mark.parametrize("raw,host,scheme,port", [
    ("scanme.nmap.org", "scanme.nmap.org", None, None),
    ("https://example.com:8443/login", "example.com", "https", 8443),
    ("45.33.32.156", "45.33.32.156", None, None),
    ("[::1]:8080", "::1", None, 8080),
])
def test_parse_target_valid(raw, host, scheme, port):
    t = parse_target(raw)
    assert (t.host, t.scheme, t.port) == (host, scheme, port)


@pytest.mark.parametrize("raw", [
    "", "-iL /etc/passwd", "--script=evil", "a b", "10.0.0.0/24", "ftp://x.com",
    "exa_mple.com", "host;rm -rf ~", "example.com:99999",
])
def test_parse_target_rejects_dangerous_or_invalid(raw):
    with pytest.raises(ValueError):
        parse_target(raw)


def test_target_url():
    assert parse_target("example.com").url("https") == "https://example.com/"
    assert parse_target("https://example.com:8443").url() == "https://example.com:8443/"


# --- authorization + audit --------------------------------------------------

def test_authorization_requires_exact_yes(tmp_path):
    t = parse_target("scanme.nmap.org")
    assert authorization.confirm_authorization(t, ["nmap"], tmp_path, input_func=lambda _: "yes")
    assert not authorization.confirm_authorization(t, ["nmap"], tmp_path, input_func=lambda _: "y")
    lines = [json.loads(l) for l in (tmp_path / "audit.log").read_text().splitlines()]
    assert [l["confirmed"] for l in lines] == [True, False]
    assert lines[0]["target"] == "scanme.nmap.org" and "timestamp_utc" in lines[0]


def test_declined_authorization_scans_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "no")
    rc = cli.main(["webcheck", "-o", str(tmp_path), "example.com"])
    assert rc == 1
    assert not (tmp_path / "example.com").exists()  # no results folder was created


# --- nmap -------------------------------------------------------------------

def test_nmap_parse_and_explain():
    hosts = nmap_scan.parse_nmap_xml(NMAP_XML)
    assert hosts[0]["address"] == "45.33.32.156"
    assert {p["port"] for p in hosts[0]["ports"]} == {22, 23, 80, 9929, 31337}
    findings = nmap_scan.explain_ports(hosts)
    by_title = {f.title: f for f in findings}
    telnet = next(f for f in findings if "Telnet" in f.title)
    assert telnet.severity == "high"
    ssh = next(f for f in findings if "SSH" in f.title)
    assert "OpenSSH 6.6.1p1" in ssh.evidence
    assert any("nvd.nist.gov" in r for r in ssh.references)
    assert any("tcpwrapped" in f.what_it_means for f in findings)
    assert any("995 closed" in t for t in by_title)


def test_nmap_host_down():
    findings = nmap_scan.explain_ports(nmap_scan.parse_nmap_xml("<nmaprun></nmaprun>"))
    assert "down" in findings[0].title


def test_nmap_command_has_no_shell_and_validates_ports(tmp_path):
    t = parse_target("scanme.nmap.org")
    cmd = nmap_scan.build_command("nmap", t, tmp_path / "x.xml", ports="22,80")
    assert cmd[-1] == "scanme.nmap.org" and "-p" in cmd
    with pytest.raises(ValueError):
        nmap_scan.build_command("nmap", t, tmp_path / "x.xml", ports="22;reboot")


# --- nuclei -----------------------------------------------------------------

def test_nuclei_groups_and_explains():
    lines = [
        {"template-id": "CVE-2021-41773", "matched-at": "http://t/cgi-bin/.%2e/etc/passwd",
         "info": {"name": "Apache 2.4.49 Path Traversal", "severity": "critical",
                  "description": "Path traversal in Apache 2.4.49.",
                  "classification": {"cve-id": ["cve-2021-41773"], "cvss-score": 7.5},
                  "remediation": "Upgrade to Apache 2.4.51 or later."}},
        {"template-id": "http-missing-security-headers", "matcher-name": "strict-transport-security",
         "matched-at": "http://t/", "info": {"name": "HTTP Missing Security Headers", "severity": "info"}},
        {"template-id": "http-missing-security-headers", "matcher-name": "x-frame-options",
         "matched-at": "http://t/", "info": {"name": "HTTP Missing Security Headers", "severity": "info"}},
    ]
    text = "\n".join(json.dumps(l) for l in lines) + "\nnot json\n"
    findings = nuclei_scan.explain_nuclei(nuclei_scan.parse_nuclei_jsonl(text))
    assert len(findings) == 2  # the two header matches are grouped
    crit = next(f for f in findings if f.severity == "critical")
    assert "CVE-2021-41773" in crit.what_it_means and "VERIFY" in crit.next_step
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" in crit.references
    headers = next(f for f in findings if f.severity == "info")
    assert "x-frame-options" in headers.evidence


# --- nikto ------------------------------------------------------------------

def test_nikto_tolerates_trailing_commas_and_explains():
    raw = """[{"host":"scanme.nmap.org","ip":"45.33.32.156","port":"80","banner":"Apache/2.4.7 (Ubuntu)",
      "vulnerabilities":[
        {"id":"999986","method":"GET","url":"/","msg":"The anti-clickjacking X-Frame-Options header is not present."},
        {"id":"600050","method":"HEAD","url":"/","msg":"Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.58)."},
        {"id":"000123","method":"GET","url":"/weird","msg":"Something unusual was found."},
      ]}]"""
    findings = nikto_scan.explain_nikto(nikto_scan.load_nikto_json(raw))
    titles = [f.title for f in findings]
    assert any("Clickjacking" in t for t in titles)
    assert any(f.title == "Outdated server software" and f.severity == "medium" for f in findings)
    assert any("Something unusual" in t for t in titles)  # unknown message still explained
    assert any("Apache/2.4.7" in t for t in titles)       # banner


# --- testssl ----------------------------------------------------------------

def test_testssl_explains_known_ids_and_counts_passes():
    entries = [
        {"id": "TLS1", "ip": "x/1.2.3.4", "port": "443", "severity": "LOW", "finding": "offered (deprecated)"},
        {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
        {"id": "SWEET32", "severity": "LOW", "finding": "VULNERABLE, uses 64 bit block ciphers",
         "cve": "CVE-2016-2183 CVE-2016-6329"},
        {"id": "cert_keySize <cert#1>", "severity": "INFO", "finding": "RSA 2048 bits"},
        {"id": "some_random_info", "severity": "INFO", "finding": "noise"},
        {"id": "weird_new_check", "severity": "HIGH", "finding": "bad"},
    ]
    findings = testssl_scan.explain_testssl(entries)
    titles = [f.title for f in findings]
    assert any(t.startswith("TLS 1.0") for t in titles)
    assert any(t.startswith("SWEET32") for t in titles)
    assert any(t.startswith("Certificate key size") for t in titles)
    assert not any("noise" in t for t in titles)
    assert any(f.title.startswith("weird_new_check") and f.severity == "high" for f in findings)
    assert any("1 TLS checks passed" in t for t in titles)


# --- webcheck (no network: fake response objects) ---------------------------

class FakeResp:
    def __init__(self, url, headers, history=(), cookies=()):
        self.url, self.status_code = url, 200
        self.headers = {k: v for k, v in headers.items()}
        self.history = list(history)
        self._cookies = list(cookies)
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: self._cookies))


def test_webcheck_http_only_site():
    http = FakeResp("http://scanme.nmap.org/", {"Server": "Apache/2.4.7 (Ubuntu)"},
                    cookies=["session=abc; Path=/"])
    findings = webcheck.explain_http(http, None)
    titles = [f.title for f in findings]
    assert "Website is only available over unencrypted HTTP" in titles
    assert any("reveals software version" in t for t in titles)
    assert not any("Strict-Transport-Security" in t for t in titles)  # HSTS irrelevant on HTTP
    assert any("Cookie 'session'" in t for t in titles)


def test_webcheck_good_https_site():
    good = {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}
    https = FakeResp("https://example.com/", good, cookies=["s=1; Secure; HttpOnly; SameSite=Lax"])
    http = FakeResp("https://example.com/", good)
    findings = webcheck.explain_http(http, https)
    assert [f.title for f in findings] == ["HTTP redirects to HTTPS"]


def test_webcheck_tls_explanations():
    facts = {"host": "h", "port": 443, "reachable": True, "protocol": "TLSv1.3",
             "cipher": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256, "cert_verified": True,
             "cert": {"issuer": {"organizationName": "Let's Encrypt"}, "not_after": "x", "days_left": 5,
                      "subject": {}, "san": ["h"]},
             "legacy_protocols": {"TLSv1.0": True, "TLSv1.1": None}}
    findings = webcheck.explain_tls(facts)
    sev = {f.title: f.severity for f in findings}
    assert sev["HTTPS negotiated TLSv1.3 with cipher TLS_AES_256_GCM_SHA384"] == "info"
    assert sev["Server still accepts TLSv1.0"] == "medium"
    assert sev["Certificate expires in 5 day(s)"] == "high"
    assert not any("TLSv1.1" in t for t in sev)  # inconclusive tests aren't reported as findings
    assert webcheck.explain_tls({"host": "h", "port": 443, "reachable": False})[0].title.startswith("No HTTPS")


# --- planning + report ------------------------------------------------------

def test_missing_tools_fall_back(monkeypatch):
    monkeypatch.setattr("reconkit.tooling.find_tool", lambda key: None)
    plan, skipped = cli.plan_modules(["nmap", "nikto", "testssl", "webcheck"])
    assert plan == ["pyports", "webcheck"]  # webcheck is deduplicated
    assert {r.module for r in skipped} == {"nmap", "nikto", "testssl"}


def test_report_escapes_hostile_tool_output(tmp_path):
    t = parse_target("example.com")
    evil = Finding("nikto", "<script>alert(1)</script>", "high", "w", "y", "n", evidence="<img src=x>")
    paths = write_reports(tmp_path, t, [ModuleResult("nikto", True, [evil])], datetime.now(), datetime.now())
    page = paths["html"].read_text()
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "[HIGH] <script>" in paths["markdown"].read_text()
    assert json.loads(paths["json"].read_text())["target"] == "example.com"
