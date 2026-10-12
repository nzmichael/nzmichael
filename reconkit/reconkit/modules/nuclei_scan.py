"""nuclei: template-based vulnerability scanner from ProjectDiscovery.

Each nuclei "template" is a small YAML file describing one check: send this
request, and if the response matches that pattern, report it. Thousands of
community templates exist, many for specific CVEs.

Output: we ask for JSON Lines (-jsonl): one JSON object per finding per line.
"""

from __future__ import annotations

import json
from pathlib import Path

from reconkit import tooling
from reconkit.findings import Finding, ModuleResult, normalize_severity
from reconkit.modules.base import run_command
from reconkit.target import Target

NAME = "nuclei"
TOOL = "nuclei"

WHY_BY_SEVERITY = {
    "critical": "Critical issues are usually directly exploitable - often remote code execution "
                "or full data access - and are actively hunted by attackers.",
    "high": "High-severity issues can lead to serious compromise, such as data exposure or "
            "account takeover.",
    "medium": "Medium issues weaken security or help an attacker, usually needing extra "
              "conditions to exploit.",
    "low": "Low issues are minor weaknesses - worth fixing in normal maintenance.",
    "info": "Informational results are facts about the target (technologies, versions, "
            "configuration). Not vulnerabilities, but they are what an attacker collects first.",
}


def build_command(binary: str, target: Target, out_path: Path, severity: str = "") -> list[str]:
    cmd = [
        binary,
        "-u", target.url() if target.scheme else target.host,
        "-jsonl",                 # one JSON object per line, easy to parse
        "-o", str(out_path),
        "-silent",                # findings only, no banner
        "-no-color",
        "-rate-limit", "50",      # max requests/second - be polite to the target
        # Skip templates tagged as potentially disruptive. Safety first.
        "-exclude-tags", "dos,intrusive,fuzz",
    ]
    if severity:
        cmd += ["-severity", severity]
    return cmd


def parse_nuclei_jsonl(text: str) -> list[dict]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # skip any non-JSON line rather than failing the whole parse
    return results


def explain_nuclei(results: list[dict], module: str = NAME) -> list[Finding]:
    # One template can match several times (e.g. one per missing header). Group
    # them by template-id so you get one explanation with all the matches.
    grouped: dict[str, list[dict]] = {}
    for r in results:
        grouped.setdefault(r.get("template-id") or r.get("templateID") or "unknown", []).append(r)

    findings = []
    for template_id, matches in grouped.items():
        info = matches[0].get("info", {}) or {}
        sev = normalize_severity(info.get("severity"))
        name = info.get("name") or template_id
        description = (info.get("description") or "").strip()
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        cves = [cves] if isinstance(cves, str) else cves
        cvss = classification.get("cvss-score")

        what = description or f"Nuclei's '{template_id}' check matched this target."
        if cves:
            what += (f" This corresponds to {', '.join(c.upper() for c in cves)} - a CVE "
                     "(Common Vulnerabilities and Exposures) ID, the public catalogue number for a "
                     "known vulnerability.")
        why = WHY_BY_SEVERITY[sev]
        if cvss:
            why += f" CVSS score: {cvss} out of 10."

        remediation = (info.get("remediation") or "").strip()
        if sev == "info":
            nxt = remediation or "No fix needed, but confirm this information is expected to be public."
        else:
            nxt = ("First VERIFY it - scanners produce false positives. Open the matched URL and "
                   "read the template (`nuclei -tl -id " + template_id + "` shows where it is). ")
            nxt += remediation or "Then apply the vendor's patch or recommended configuration change."

        locations = sorted({m.get("matched-at") or m.get("host", "") for m in matches})
        matchers = sorted({m.get("matcher-name") for m in matches if m.get("matcher-name")})
        evidence = f"template={template_id} matched at: {', '.join(locations[:5])}"
        if matchers:
            evidence += f" | details: {', '.join(matchers[:10])}"

        refs = list(info.get("reference") or [])[:3] if isinstance(info.get("reference"), list) else []
        refs += [f"https://nvd.nist.gov/vuln/detail/{c.upper()}" for c in cves]
        findings.append(Finding(module, name, sev, what, why, nxt, evidence=evidence, references=refs))
    return findings


def run(target: Target, outdir: Path, options) -> ModuleResult:
    binary = tooling.find_tool(TOOL)
    if not binary:
        return ModuleResult(NAME, ran=False, note="nuclei is not installed.")
    out = outdir / "nuclei.jsonl"
    cmd = build_command(binary, target, out, getattr(options, "severity", "") or "")
    res = run_command(cmd, outdir, "nuclei", timeout=getattr(options, "timeout", 1800))
    result = ModuleResult(NAME, ran=True, command=" ".join(cmd), raw_files=[str(out)])
    if res.returncode not in (0,) and not out.exists():
        result.ran = False
        result.note = f"nuclei failed (exit code {res.returncode}). See nuclei.log. {res.stderr.strip()[:300]}"
        return result
    text = out.read_text(encoding="utf-8", errors="replace") if out.exists() else ""
    result.findings = explain_nuclei(parse_nuclei_jsonl(text))
    return result
