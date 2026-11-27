"""Mission runner tests. The model is a scripted test double so the control flow can be checked exactly."""
import json
import time

import pytest

from fusion_os.llm import LLMUnavailable, Router
from fusion_os.memory import MemoryStore
from fusion_os.missions import MissionLimits, MissionRunner, Tool
from fusion_os.security.controller import SecurityController


class Scripted:
    name = "scripted"

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def complete(self, system, prompt, max_tokens=2000):
        self.calls.append((system, prompt))
        return self.handler(system, prompt, len(self.calls))


def setup(tmp_path, handler, **lim):
    ctl = SecurityController(tmp_path / "s")
    mem = MemoryStore(tmp_path / "m.db")
    llm = Scripted(handler)
    r = MissionRunner(ctl, mem, llm, tmp_path / "missions.db", limits=MissionLimits(**lim))
    return ctl, mem, llm, r


PLAN = {"strategy": "draft then review", "steps": [
    {"id": 1, "role": "writer", "tool": "think", "inputs": {"task": "draft"}, "expected": "a draft"},
    {"id": 2, "role": "reviewer", "tool": "think", "inputs": {"task": "review"}, "expected": "a review"}]}


def test_mission_succeeds_with_verification_and_learning(tmp_path):
    def h(system, prompt, n):
        if "planning agent" in system:
            return "```json\n" + json.dumps(PLAN) + "\n```"
        if "independent reviewer" in system:
            return '{"score": 7, "reason": "ok"}'
        if "verifier" in system:
            return '{"pass": true, "reason": "fine"}'
        return "WORK OUTPUT"
    ctl, mem, llm, r = setup(tmp_path, h)
    mid = r.start("write a product announcement", background=False)
    m = r.get(mid)
    assert m["status"] == "succeeded", m["error"]
    assert m["team"] == ["reviewer", "writer"]
    assert m["result"]["final"] == "WORK OUTPUT"
    assert mem.lessons("product announcement")["worked"]
    assert ctl.budgets.get(mid)["used_calls"] >= 3
    assert all(not a["revoked"] is False for a in ctl.list_agents())  # mission agents revoked at the end
    assert ctl.audit.verify()["ok"]


def test_failed_step_triggers_replan(tmp_path):
    state = {"verify": 0, "plans": 0}
    def h(system, prompt, n):
        if "planning agent" in system:
            state["plans"] += 1
            return json.dumps(PLAN)
        if "independent reviewer" in system:
            return '{"score": 5}'
        if "verifier" in system:
            state["verify"] += 1
            return '{"pass": false, "reason": "too vague"}' if state["verify"] == 1 else '{"pass": true}'
        return "x"
    ctl, mem, llm, r = setup(tmp_path, h)
    mid = r.start("goal", background=False)
    m = r.get(mid)
    assert m["status"] == "succeeded"
    assert any(e["event"] == "replan" for e in m["log"])
    assert state["plans"] == 3  # 2 candidates + 1 replan


def test_replan_limit_then_failure_is_learned(tmp_path):
    def h(system, prompt, n):
        if "planning agent" in system:
            return json.dumps(PLAN)
        if "verifier" in system:
            return '{"pass": false, "reason": "wrong"}'
        return '{"score": 1}'
    ctl, mem, llm, r = setup(tmp_path, h, max_replans=1)
    mid = r.start("impossible goal", background=False)
    m = r.get(mid)
    assert m["status"] == "failed" and "replans" in m["error"]
    assert mem.lessons("impossible goal")["failed"]


def test_unknown_tool_and_policy_denied_plans_rejected(tmp_path):
    bad = {"strategy": "x", "steps": [{"id": 1, "role": "w", "tool": "rm_rf", "inputs": {}}]}
    ctl, mem, llm, r = setup(tmp_path, lambda s, p, n: json.dumps(bad))
    mid = r.start("goal", background=False)
    assert "no valid plan" in r.get(mid)["error"]
    r.register_tool(Tool("buy", "market.purchase", "buy things", lambda i, c: None))
    assert any("policy would deny" in p for p in r._dry_run({"steps": [{"id": 1, "tool": "buy"}]}, r._available_tools()))


def test_limits_team_and_steps(tmp_path):
    big = {"strategy": "x", "steps": [{"id": i, "role": f"r{i}", "tool": "think", "inputs": {}} for i in range(1, 9)]}
    ctl, mem, llm, r = setup(tmp_path, lambda s, p, n: json.dumps(big), max_team=3, max_steps=5)
    assert {"too many steps", "team too large"} <= set(r._dry_run(big, r._available_tools()))


def test_emergency_stop_halts_mission(tmp_path):
    ctl, mem, llm, r = setup(tmp_path, lambda s, p, n: json.dumps(PLAN) if "planning" in s else '{"score":1}')
    ctl.emergency_stop("admin", "t")
    mid = r.start("goal", background=False)
    assert r.get(mid)["status"] == "stopped"


def test_no_model_blocks_honestly(tmp_path):
    ctl = SecurityController(tmp_path / "s")
    r = MissionRunner(ctl, MemoryStore(tmp_path / "m.db"), Router([]), tmp_path / "x.db")
    mid = r.start("goal", background=False)
    m = r.get(mid)
    assert m["status"] == "blocked" and "no model" in m["error"]


def test_router_falls_back():
    class Bad:
        name = "bad"
        def complete(self, *a, **k):
            raise RuntimeError("down")
    class Good:
        name = "good"
        def complete(self, *a, **k):
            return "hi"
    rt = Router([Bad(), Good()])
    assert rt.complete("s", "p") == "hi" and rt.last["provider"] == "good" and rt.last["fallbacks"]
    with pytest.raises(LLMUnavailable):
        Router([Bad()]).complete("s", "p")


from fusion_os.sandbox import DockerSandbox
from fusion_os.skills import SkillManager

DOCKER = DockerSandbox().available()[0]

REVERSE = {
    "skill.json": json.dumps({"name": "reverse-text", "version": "1.0.0", "description": "Reverse a text string",
                              "license": "MIT", "example_input": {"text": "abc"}, "capabilities": ["reverse text"]}),
    "main.py": "import json, sys\nd = json.loads(sys.stdin.read() or '{}')\nprint(json.dumps({'reversed': str(d.get('text', ''))[::-1]}))\n",
    "test_main.py": "import unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.assertEqual('abc'[::-1], 'cba')\n",
}


@pytest.mark.skipif(not DOCKER, reason="docker daemon not available")
def test_capability_gap_acquires_skill_then_completes(tmp_path):
    def h(system, prompt, n):
        if "planning agent" in system:
            tool = "skill:reverse-text" if "skill:reverse-text" in prompt else "missing:reverse text"
            return json.dumps({"strategy": "s", "steps": [{"id": 1, "role": "worker", "tool": tool, "inputs": {"text": "hello"}}]})
        if "write small, safe Python skills" in system:
            return json.dumps({"files": REVERSE})
        if "independent reviewer" in system:
            return '{"score": 5}'
        return "done"
    ctl = SecurityController(tmp_path / "s")
    skm = SkillManager(ctl, tmp_path / "skills")
    r = MissionRunner(ctl, MemoryStore(tmp_path / "m.db"), Scripted(h), tmp_path / "x.db", skills=skm)
    mid = r.start("reverse the word hello", background=False)
    m = r.get(mid)
    assert m["status"] == "waiting", m
    w = m["waiting_on"][0]
    assert w["skill"] == "reverse-text"
    assert ctl.decide_approval(w["approval_id"], True, "admin")
    assert r.complete_skill_registration(mid)[0]["allowed"]
    r.resume(mid, background=False)
    m = r.get(mid)
    assert m["status"] == "succeeded", m["error"]
    assert m["result"]["steps"]["1"] == {"reversed": "olleh"}
