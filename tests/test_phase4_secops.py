import json
import subprocess
import time

import pytest

from fusion_os.sandbox import DockerSandbox
from fusion_os.secops import SecOpsService
from fusion_os.secops.tools import nmap_parse, semgrep_parse, trivy_parse, nuclei_parse
from fusion_os.security.controller import SecurityController
from fusion_os.security.engagements import Engagement

NMAP_XML = """<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.7" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port></ports></host></nmaprun>"""


def test_parsers():
    f = nmap_parse(NMAP_XML, "10.0.0.7")
    assert len(f) == 2 and {x["severity"] for x in f} == {"info", "high"} and f[0]["attack"] == "T1046"
    sg = {"results": [{"check_id": "python.lang.security.audit.eval-detected", "path": "a.py", "start": {"line": 3},
                       "extra": {"severity": "ERROR", "message": "eval", "lines": "eval(x)", "metadata": {"owasp": ["A03:2021 - Injection"]}}}]}
    assert semgrep_parse(json.dumps(sg), "x")[0]["severity"] == "high"
    tv = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "jinja2",
          "InstalledVersion": "2.0", "FixedVersion": "3.1.6", "Severity": "CRITICAL", "Title": "t"}]}]}
    assert "Upgrade jinja2 to 3.1.6" in trivy_parse(json.dumps(tv), "x")[0]["remediation"]
    nu = json.dumps({"template-id": "x", "matched-at": "https://a", "info": {"name": "Exposed panel", "severity": "medium"}})
    assert nuclei_parse(nu, "a")[0]["severity"] == "medium"


@pytest.fixture
def svc(tmp_path):
    ctl = SecurityController(tmp_path / "s")
    tok = ctl.register_agent("sec1", ["security"])
    return ctl, ctl.agent_for_token(tok), SecOpsService(ctl, tmp_path / "secops.db", tmp_path / "analysis")


def test_out_of_scope_scan_is_refused_before_any_container(svc):
    ctl, agent, s = svc
    s.docker_bin = "/nonexistent"  # would raise if it got as far as running
    e = ctl.create_engagement(Engagement(name="t", authorized_by="Owner", authorization_ref="REF-1", targets=["10.9.9.0/24"],
                                         allowed_tools=["nmap"], ends_at=time.time() + 600), "admin")
    r = s.run_tool(agent, "nmap", target="8.8.8.8", engagement_id=e.id)
    assert not r["verdict"]["allowed"] and "allowlist" in r["verdict"]["reason"]
    r = s.run_tool(agent, "nuclei", target="10.9.9.1", engagement_id=e.id)
    assert "not authorized" in r["verdict"]["reason"]
    assert not s.run_tool(agent, "nmap", target="10.9.9.1")["verdict"]["allowed"]


def test_suricata_ingest(svc):
    _, _, s = svc
    eve = "\n".join([json.dumps({"timestamp": "2026-11-27T10:00:00", "event_type": "alert", "src_ip": "1.2.3.4", "src_port": 4444,
                                 "dest_ip": "10.0.0.2", "dest_port": 22, "alert": {"signature": "ET SCAN SSH brute force", "severity": 2,
                                 "category": "Attempted Admin", "metadata": {"mitre_technique_id": ["T1110"]}}}),
                     json.dumps({"event_type": "flow"})])
    assert s.ingest_suricata(eve) == 1 and s.ingest_suricata(eve) == 0
    a = s.alerts()
    assert a["alerts"][0]["attack"] == "T1110" and a["by_severity"]["medium"] == 1


def _docker_ok():
    sb = DockerSandbox(allowed_images=("instrumentisto/nmap:7.95",))
    if not sb.available()[0]:
        return False
    for img in ("instrumentisto/nmap:7.95", "nginx:alpine"):
        if subprocess.run(["docker", "image", "inspect", img], capture_output=True).returncode != 0:
            return False
    return True


@pytest.mark.skipif(not _docker_ok(), reason="docker or images not available")
def test_live_nmap_scan_report_and_verification(svc):
    ctl, agent, s = svc
    cid = subprocess.run(["docker", "run", "-d", "--rm", "nginx:alpine"], capture_output=True, text=True).stdout.strip()
    try:
        ip = subprocess.run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                            capture_output=True, text=True).stdout.strip()
        e = ctl.create_engagement(Engagement(name="lab web server", authorized_by="Lab owner", authorization_ref="LAB-001",
                                             targets=[f"{ip}/32"], allowed_tools=["nmap"], ends_at=time.time() + 600), "admin")
        r = s.run_tool(agent, "nmap", target=ip, engagement_id=e.id, options={"ports": "80,443,6379"}, timeout_s=180)
        assert r["verdict"]["allowed"] and r["run"]["exit_code"] == 0, r
        titles = [f["title"] for f in r["findings"]]
        assert any("Open port 80" in t for t in titles), titles
        rep = s.report(e.id)
        assert "LAB-001" in rep and "Open port 80" in rep and "Audit log chain verified: True" in rep
        fid = s.findings(e.id)[0]["id"]
        v = s.verify_finding(agent, fid)
        assert v["verdict"]["effect"] == "pending_approval"
        ctl.decide_approval(v["verdict"]["approval_id"], True, "admin")
        v2 = s.verify_finding(agent, fid, approval_id=v["verdict"]["approval_id"])
        assert v2["still_present"] and s.get_finding(fid)["status"] == "verified"
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
