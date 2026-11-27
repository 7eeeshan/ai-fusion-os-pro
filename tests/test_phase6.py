import json
import zipfile

import httpx
import pytest

from fusion_os.config_store import ConfigStore
from fusion_os.intel import TechIntelAgent, TechRegistry
from fusion_os.memory import MemoryStore
from fusion_os.models import ModelManager
from fusion_os.models.bench import BUILTIN_SUITES, BenchmarkSuite
from fusion_os.ops import BackupManager, HealthMonitor, ImprovementLab
from fusion_os.security.controller import SecurityController


@pytest.fixture
def ctl(tmp_path):
    return SecurityController(tmp_path / "home" / "security")


def api(req: httpx.Request) -> httpx.Response:
    u = str(req.url)
    if "pypi.org/pypi/fastapi" in u:
        return httpx.Response(200, json={"info": {"version": "0.162.2", "license_expression": "MIT", "requires_python": ">=3.9"},
                                         "urls": [{"upload_time_iso_8601": "2026-11-20T00:00:00Z"}]})
    if "api.osv.dev" in u:
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-x"}]})
    if "api.github.com/repos/ollama/ollama/releases" in u:
        return httpx.Response(200, json={"tag_name": "v0.20.0", "published_at": "2026-11-25T00:00:00Z"})
    if "api.github.com/repos/ollama/ollama" in u:
        return httpx.Response(200, json={"html_url": "https://github.com/ollama/ollama", "stargazers_count": 150000,
                                         "license": {"spdx_id": "MIT"}, "archived": False, "pushed_at": "2026-11-26T00:00:00Z"})
    return httpx.Response(404)


def test_tech_intel_registry_and_reevaluation(ctl, tmp_path):
    reg = TechRegistry(tmp_path / "t.db")
    ag = TechIntelAgent(ctl, reg, client=httpx.Client(transport=httpx.MockTransport(api)))
    rep = ag.scan({"github": ["ollama/ollama"], "pypi": ["fastapi", "nope-pkg"]})
    assert len(rep["ok"]) == 2 and len(rep["errors"]) == 1
    items = {i["name"]: i for i in reg.list()}
    o = items["ollama/ollama"]
    assert o["status"] == "evaluated" and o["scores"]["licensing"] == 10 and o["scores"]["maintenance"] == 10
    assert "hardware" in o["unscored"]  # never invented
    f = items["pypi:fastapi"]
    assert f["facts"]["known_vulns"] == ["GHSA-x"] and f["scores"]["security"] == 7
    reg.set_status(o["id"], "approved")
    reg.upsert("repository", "ollama/ollama", "github", "", "v0.21.0")
    assert reg.list(kind="repository")[0]["status"] == "available"  # new version must be re-evaluated


class FakeModels:
    """Benchmark provider test double: model 'good' answers correctly, 'bad' does not."""
    def __call__(self, model, system, prompt):
        if model == "bad":
            return "I am not sure."
        answers = {"17 * 23": "391", "capital of Australia": "Canberra", "JSON": '{"ok": true, "n": 3}',
                   "Reverse": "noisuf", "prime": "Yes", "Summarise": "A prompt injection attempt."}
        return next(v for k, v in answers.items() if k in prompt)


def test_benchmark_compare_deploy_rollback(ctl, tmp_path):
    cfg = ConfigStore(tmp_path / "c.db")
    mm = ModelManager(ctl, cfg, tmp_path / "b.db", {"local": FakeModels()})
    suite = BUILTIN_SUITES["general-v1"]
    assert mm.run(suite, "local", "good")["accuracy"] == 1.0
    assert mm.run(suite, "local", "bad")["accuracy"] < 0.5
    agent = ctl.agent_for_token(ctl.register_agent("ops", ["standard"]))
    v = mm.deploy(agent, "default", "local", "bad")
    ctl.decide_approval(v["approval_id"], True, "admin")
    assert mm.deploy(agent, "default", "local", "bad", v["approval_id"])["allowed"]
    cmp = mm.compare(suite, {"provider": "local", "model": "good"})
    assert cmp["recommend"] and "accuracy" in cmp["reason"]
    assert not mm.compare(suite, {"provider": "local", "model": "bad"})["recommend"]
    v = mm.deploy(agent, "default", "local", "good")
    ctl.decide_approval(v["approval_id"], True, "admin")
    mm.deploy(agent, "default", "local", "good", v["approval_id"])
    assert mm.deployed()["model"] == "good"
    assert mm.rollback()["model"] == "bad" and mm.deployed()["model"] == "bad"


def test_improvement_lab_validate_approve_and_auto_rollback(ctl, tmp_path):
    cfg = ConfigStore(tmp_path / "c.db")
    cfg.set("prompt.worker", "old prompt", "admin")
    score = {"old prompt": 0.5, "better prompt": 0.8, "worse prompt": 0.2}
    healthy = {"v": True}
    lab = ImprovementLab(ctl, cfg, tmp_path / "p.db", lambda k, v: score.get(v, 0), post_check=lambda: healthy["v"])
    agent = ctl.agent_for_token(ctl.register_agent("improver", ["standard"]))
    with pytest.raises(PermissionError):
        lab.propose("prompt", "policy.rules", "x", "r", "improver")
    bad = lab.propose("prompt", "prompt.worker", "worse prompt", "shorter", "improver")
    assert lab.validate(bad)["status"] == "rejected"
    with pytest.raises(ValueError):
        lab.apply(bad, agent)
    good = lab.propose("prompt", "prompt.worker", "better prompt", "clearer", "improver")
    assert lab.validate(good)["status"] == "validated"
    v = lab.apply(good, agent)
    assert v["effect"] == "pending_approval"
    ctl.decide_approval(v["approval_id"], True, "admin")
    assert lab.apply(good, agent, v["approval_id"])["applied"] and cfg.get("prompt.worker") == "better prompt"
    # a change that breaks the post-apply check is rolled back automatically
    healthy["v"] = False
    score["best prompt"] = 0.9
    p3 = lab.propose("prompt", "prompt.worker", "best prompt", "x", "improver")
    lab.validate(p3)
    v = lab.apply(p3, agent)
    ctl.decide_approval(v["approval_id"], True, "admin")
    r = lab.apply(p3, agent, v["approval_id"])
    assert r["rolled_back"] and cfg.get("prompt.worker") == "better prompt"


def test_health_diagnose_heal(ctl, tmp_path):
    mem = MemoryStore(tmp_path / "m.db")
    for _ in range(2):
        mem.record_episode("sync crm", ["x"], "failure", error="HTTP 401 from CRM")
    hm = HealthMonitor(ctl, memory=mem, data_dir=tmp_path)
    assert hm.check()["ok"]
    d = hm.diagnose()
    assert any("Recurring" in a for a in d["advice"])
    (ctl.dir / "policy.json").write_text('{"version": 9, "rules": []}')
    assert not hm.check()["ok"]
    assert any("Policy" in a for a in hm.diagnose()["advice"])
    assert hm.heal() == []  # cannot "heal" a tampered policy: that needs the admin


def test_backup_and_restore(ctl, tmp_path):
    home = tmp_path / "home"
    mem = MemoryStore(home / "memory.db")
    mem.write("before backup", source="t")
    bm = BackupManager(home, ctl)
    name = bm.create("test")
    with zipfile.ZipFile(home / "backups" / name) as z:
        assert "memory.db" in z.namelist() and "security/policy.json" in z.namelist()
    mem.write("zebra stripes", source="t")
    mem.conn.close()
    res = bm.restore(name)
    assert res["restored"] > 0 and res["safety_backup"]
    m2 = MemoryStore(home / "memory.db")
    assert m2.search("before backup") and not m2.search("zebra")
