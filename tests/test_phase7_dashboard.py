"""Every dashboard section calls these endpoints; all must answer from real backends."""
import re
from pathlib import Path

from fastapi.testclient import TestClient

from fusion_os.api.server import create_app
from fusion_os.sandbox import DockerSandbox
from fusion_os.security.controller import SecurityController

HTML = (Path(__file__).parent.parent / "fusion_os" / "api" / "dashboard.html").read_text(encoding="utf-8")


def test_dashboard_served_with_security_headers(tmp_path):
    c = TestClient(create_app(SecurityController(tmp_path / "s"), DockerSandbox(docker_bin="/nope")))
    r = c.get("/dashboard")
    assert r.status_code == 200 and "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_every_dashboard_get_endpoint_works(tmp_path):
    ctl = SecurityController(tmp_path / "s")
    c = TestClient(create_app(ctl, DockerSandbox(docker_bin="/nope")))
    adm = {"Authorization": f"Bearer {ctl.admin_token()}"}
    ag = {"Authorization": "Bearer " + c.post("/admin/agents", json={"agent_id": "dashboard", "zones": ["research", "security", "standard"]}, headers=adm).json()["token"]}
    paths = set(re.findall(r'api\("(/[a-z0-9/_\-]+)(?:\?[^"]*)?"\)', HTML)) | set(re.findall(r'api\("(/[a-z0-9/_\-]+)(?:\?[^"]*)?",\{\},true\)', HTML))
    agent_paths = set(re.findall(r'api\("(/v1/[a-z0-9/_\-]+)', HTML))
    assert len(paths) >= 18
    for p in sorted(paths):
        r = c.get(p, headers=ag if p in agent_paths else adm)
        assert r.status_code == 200, (p, r.status_code, r.text[:200])
    for p, h in [("/admin/approvals?status=pending", adm), ("/admin/research/evidence?darkweb=true", adm),
                 ("/admin/secops/findings?status=open", adm), ("/v1/memory/graph?node=x&depth=2", ag)]:
        assert c.get(p, headers=h).status_code == 200, p
