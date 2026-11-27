"""Security tool adapters. Each tool runs in its own pinned container image inside the sandbox; adapters only build
the command line and parse the tool's machine-readable output into findings."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")

# Exposed services that usually deserve attention, with remediation advice.
RISKY_PORTS = {
    21: ("medium", "FTP exposed", "Disable FTP or replace it with SFTP; never allow anonymous login."),
    23: ("high", "Telnet exposed", "Disable Telnet and use SSH."),
    445: ("high", "SMB exposed", "Do not expose SMB beyond the internal network; apply current patches."),
    3389: ("medium", "RDP exposed", "Put RDP behind a VPN or gateway with MFA; enable NLA."),
    5900: ("medium", "VNC exposed", "Restrict VNC to a VPN and require strong authentication."),
    6379: ("high", "Redis exposed", "Bind Redis to localhost or a private network and enable AUTH/ACLs."),
    9200: ("high", "Elasticsearch exposed", "Restrict access and enable security features (authentication, TLS)."),
    27017: ("high", "MongoDB exposed", "Bind to a private network and enable authentication."),
    2375: ("critical", "Docker API exposed without TLS", "Close port 2375; use TLS-protected socket access only."),
}


@dataclass
class Adapter:
    name: str
    image: str
    action: str  # policy action
    kind: str  # active | code | malware
    network: str
    build: Callable[[str, dict], list[str]]
    parse: Callable[[str, str], list[dict]]  # (stdout, target) -> findings
    env: Optional[dict] = None
    note: str = ""


def _f(title: str, severity: str, target: str, evidence: str, remediation: str, owasp: str = "", attack: str = "",
       ref: str = "") -> dict:
    return {"title": title, "severity": severity if severity in SEVERITIES else "info", "target": target,
            "evidence": evidence[:4000], "remediation": remediation, "owasp": owasp, "attack": attack, "reference": ref}


# ---------- nmap ----------
def nmap_build(target: str, o: dict) -> list[str]:
    ports = str(o.get("ports", "--top-ports=1000"))
    args = ["-sT", "-Pn", "-sV", "-T3", "--max-retries", "2", "-oX", "-"]
    args += [ports] if ports.startswith("--top-ports") else ["-p", ports]
    return args + [target]


def nmap_parse(out: str, target: str) -> list[dict]:
    findings = []
    try:
        root = ET.fromstring(out[out.find("<?xml"):] if "<?xml" in out else out)
    except ET.ParseError:
        return [_f("Scan output could not be parsed", "info", target, out[-1000:], "Re-run the scan.")]
    for host in root.findall("host"):
        addr = host.find("address").get("addr") if host.find("address") is not None else target
        for p in host.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            port = int(p.get("portid"))
            svc = p.find("service")
            desc = " ".join(filter(None, [svc.get("name") if svc is not None else "", svc.get("product", "") if svc is not None else "",
                                          svc.get("version", "") if svc is not None else ""])).strip()
            sev, title, fix = RISKY_PORTS.get(port, ("info", f"Open port {port}/{p.get('protocol')}",
                                                     "Confirm this service must be reachable; close it otherwise."))
            findings.append(_f(f"{title} ({addr}:{port})" if port in RISKY_PORTS else title + f" on {addr}", sev, f"{addr}:{port}",
                               f"nmap: {port}/{p.get('protocol')} open, service: {desc or 'unknown'}", fix,
                               owasp="WSTG-CONF-01", attack="T1046"))
    return findings


# ---------- nuclei ----------
def nuclei_parse(out: str, target: str) -> list[dict]:
    res = []
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        info = d.get("info", {})
        res.append(_f(info.get("name", d.get("template-id", "nuclei finding")), info.get("severity", "info"),
                      d.get("matched-at", target), json.dumps({k: d.get(k) for k in ("template-id", "matcher-name", "extracted-results", "curl-command")})[:3000],
                      info.get("remediation") or "See the template reference and vendor advisory.",
                      ref=", ".join(info.get("reference") or [])[:500] if isinstance(info.get("reference"), list) else str(info.get("reference") or "")))
    return res


# ---------- semgrep ----------
def semgrep_parse(out: str, target: str) -> list[dict]:
    try:
        d = json.loads(out)
    except ValueError:
        return []
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    res = []
    for r in d.get("results", []):
        ex = r.get("extra", {})
        md = ex.get("metadata", {})
        owasp = md.get("owasp", "")
        res.append(_f(r.get("check_id", "semgrep finding").split(".")[-1], sev.get(ex.get("severity", "INFO"), "low"),
                      f"{r.get('path')}:{r.get('start', {}).get('line')}", (ex.get("lines") or "")[:1500] + "\n" + ex.get("message", ""),
                      ex.get("fix") or md.get("remediation") or "Apply the secure pattern described in the rule.",
                      owasp=", ".join(owasp) if isinstance(owasp, list) else str(owasp),
                      ref=", ".join(md.get("references", []))[:500] if isinstance(md.get("references"), list) else ""))
    return res


# ---------- trivy ----------
def trivy_parse(out: str, target: str) -> list[dict]:
    try:
        d = json.loads(out)
    except ValueError:
        return []
    res = []
    for r in d.get("Results", []) or []:
        for v in r.get("Vulnerabilities", []) or []:
            fix = v.get("FixedVersion")
            res.append(_f(f"{v.get('VulnerabilityID')} in {v.get('PkgName')} {v.get('InstalledVersion')}",
                          str(v.get("Severity", "UNKNOWN")).lower(), r.get("Target", target),
                          (v.get("Title") or v.get("Description") or "")[:1500],
                          f"Upgrade {v.get('PkgName')} to {fix}." if fix else "No fixed version yet; mitigate or replace the package.",
                          owasp="A06:2021", ref=v.get("PrimaryURL", "")))
        for s in r.get("Secrets", []) or []:
            res.append(_f(f"Secret in code: {s.get('Title')}", str(s.get("Severity", "HIGH")).lower(),
                          f"{r.get('Target')}:{s.get('StartLine')}", "secret value redacted", "Revoke and rotate the secret, then remove it from history.",
                          owasp="A07:2021"))
    return res


# ---------- yara ----------
def yara_parse(out: str, target: str) -> list[dict]:
    res = []
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and not line.startswith("0x"):
            res.append(_f(f"YARA rule match: {parts[0]}", "high", parts[1], line, "Isolate the file and analyse it further; do not execute it.",
                          attack="T1204"))
    return res


ADAPTERS: dict[str, Adapter] = {
    "nmap": Adapter("nmap", "instrumentisto/nmap:7.95", "security.scan.active", "active", "bridge", nmap_build, nmap_parse),
    "nuclei": Adapter("nuclei", "projectdiscovery/nuclei:v3.4.10", "security.scan.active", "active", "bridge",
                      lambda t, o: ["-u", t, "-jsonl", "-silent", "-duc", "-severity", str(o.get("severity", "low,medium,high,critical")),
                                    "-rl", str(int(o.get("rate", 20)))],
                      nuclei_parse, env={"HOME": "/tmp"}, note="downloads templates on each run (needs egress)"),
    "semgrep": Adapter("semgrep", "semgrep/semgrep:1.140.0", "security.code.analyze", "code", "bridge",
                       lambda t, o: ["semgrep", "scan", "--config", str(o.get("config", "p/default")), "--json", "--metrics=off", "/work"],
                       semgrep_parse, env={"HOME": "/tmp", "SEMGREP_SEND_METRICS": "off"}, note="fetches rules from the Semgrep registry"),
    "trivy": Adapter("trivy", "aquasec/trivy:0.67.2", "security.code.analyze", "code", "bridge",
                     lambda t, o: ["fs", "--format", "json", "--scanners", "vuln,secret", "--cache-dir", "/tmp/trivy", "/work"],
                     trivy_parse, env={"HOME": "/tmp"}, note="downloads the vulnerability DB on each run"),
    "yara": Adapter("yara", "blacktop/yara:4.5", "security.malware.static", "malware", "none",
                    lambda t, o: ["-r", "-w", "/work/rules.yar", "/work/samples"], yara_parse,
                    note="put rules in rules.yar and files in samples/ inside the analysis folder"),
}
