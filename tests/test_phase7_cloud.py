import threading
import time

from fastapi.testclient import TestClient

from fusion_os.cloud import JobQueue, Worker
from fusion_os.cloud.llm_bridge import QueueLLM
from fusion_os.cloud.worker import RemoteQueue
from fusion_os.llm import Router


def test_idempotent_enqueue_and_schedule_slots(tmp_path):
    q = JobQueue(tmp_path / "q.db")
    a, c1 = q.enqueue("x", {}, idem="k1")
    b, c2 = q.enqueue("x", {}, idem="k1")
    assert a == b and c1 and not c2
    q.schedule("s", "x", {}, 3600)
    first = q.tick()
    assert len(first) == 1 and q.tick() == []  # second scheduler tick in the same slot adds nothing


def test_lease_expiry_moves_job_and_blocks_stale_completion(tmp_path):
    q = JobQueue(tmp_path / "q.db", lease_s=0.2)
    jid, _ = q.enqueue("work", {"n": 1})
    j = q.lease("pc", ["docker"], "local")
    assert j["id"] == jid
    time.sleep(0.3)  # the PC switched off mid-job
    j2 = q.lease("cloud-1", ["docker"], "cloud")
    assert j2["id"] == jid and j2["attempt"] == 2
    assert not q.complete(jid, "pc", "late result")  # stale worker cannot record a duplicate result
    assert q.complete(jid, "cloud-1", "ok") and q.get(jid)["status"] == "done"


def test_capability_routing_with_fallback(tmp_path):
    q = JobQueue(tmp_path / "q.db")
    jid, _ = q.enqueue("infer", {}, requires=["local-engine"], fallback_requires=[])
    q.register_node("pc", "local", ["local-engine"])
    assert q.lease("cloud-1", [], "cloud") is None  # local node alive: cloud must not take it
    q.conn.execute("UPDATE nodes SET last_seen=0 WHERE id='pc'")  # PC goes offline
    assert q.lease("cloud-1", [], "cloud")["id"] == jid


def test_worker_runs_handlers_and_retries(tmp_path):
    q = JobQueue(tmp_path / "q.db")
    calls = {"n": 0}
    def flaky(p):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return p["v"] * 2
    w = Worker(q, {"double": flaky}, [], "cloud")
    jid, _ = q.enqueue("double", {"v": 21})
    w.run_once()
    assert q.get(jid)["status"] == "queued" and "transient" in q.get(jid)["error"]
    q.conn.execute("UPDATE jobs SET run_after=0")
    w.run_once()
    assert q.get(jid)["status"] == "done" and q.get(jid)["result"] == "42"


def test_queue_llm_routes_to_live_local_node_else_falls_back(tmp_path):
    q = JobQueue(tmp_path / "q.db")
    class Cloud:
        name = "cloud"
        def complete(self, s, p, m=2000):
            return "from cloud"
    r = Router([QueueLLM(q, timeout_s=5), Cloud()])
    assert r.complete("s", "hi") == "from cloud"  # no local node
    w = Worker(q, {"llm.complete": lambda p: "from local engine: " + p["prompt"]}, ["local-engine"], "local", "pc", poll_s=0.05)
    q.register_node("pc", "local", ["local-engine"])
    t = threading.Thread(target=w.run_forever, daemon=True)
    t.start()
    try:
        out = r.complete("s", "hi")
        assert out == "from local engine: hi" and r.last["provider"] == "local-engine-via-queue", r.last
    finally:
        w.stop()


def test_remote_worker_over_http_api(tmp_path, monkeypatch):
    from fusion_os.api.server import create_app
    from fusion_os.security.controller import SecurityController
    from fusion_os.sandbox import DockerSandbox
    monkeypatch.setenv("FUSION_OS_MISSION_MODE", "queue")
    ctl = SecurityController(tmp_path / "s")
    app = create_app(ctl, DockerSandbox(docker_bin="/nope"))
    c = TestClient(app)
    adm = {"Authorization": f"Bearer {ctl.admin_token()}"}
    tok = c.post("/admin/agents", json={"agent_id": "pc-worker", "zones": ["standard"]}, headers=adm).json()["token"]
    q = app.state.queue
    jid, _ = q.enqueue("llm.complete", {"system": "s", "prompt": "p"}, requires=["local-engine"])
    rq = RemoteQueue("http://testserver", tok, client=c)
    c.headers["Authorization"] = f"Bearer {tok}"
    w = Worker(rq, {"llm.complete": lambda p: "answer"}, ["local-engine"], "local", "pc1")
    assert w.run_once()["id"] == jid
    assert q.get(jid)["status"] == "done"
    del c.headers["Authorization"]
    mid = c.post("/admin/missions", json={"goal": "summarise the backlog"}, headers=adm).json()
    assert mid["queued"] and q.stats()["by_status"]["queued"] == 1
    ov = c.get("/admin/queue", headers=adm).json()
    assert any(n["id"] == "pc-worker:pc1" and n["alive"] for n in ov["nodes"])
    assert "this_node" in c.get("/admin/resources", headers=adm).json()
