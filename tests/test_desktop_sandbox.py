"""Process sandbox (desktop app without Docker): it runs real Python children, so these tests are live."""
import json
import socket
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fusion_os.api.server import create_app
from fusion_os.memory import MemoryStore
from fusion_os.sandbox import AutoSandbox, DockerSandbox, ProcessSandbox, SandboxSpec, SandboxUnavailable
from fusion_os.security.controller import SecurityController
from fusion_os.skills import SkillManager

EX = Path(__file__).parent.parent / "examples" / "skills" / "text-stats"
IMG = "python:3.12-slim"
NO_DOCKER = DockerSandbox(docker_bin="/nope")


def run_code(tmp_path, code, **kw):
    work = tmp_path / "w"
    work.mkdir(exist_ok=True)
    (work / "main.py").write_text(code)
    sb = ProcessSandbox(workroot=tmp_path)
    return sb.run(SandboxSpec(image=IMG, command=["python", "-I", "-B", "/work/main.py"], workdir=str(work), **kw))


def test_runs_python_and_reads_its_work_folder(tmp_path):
    r = run_code(tmp_path, "import json,sys\nprint(json.dumps({'in': sys.stdin.read(), 'f': open('main.py').read()[:6]}))",
                 stdin="hello")
    assert r.exit_code == 0, r.stderr
    assert json.loads(r.stdout) == {"in": "hello", "f": "import"}


@pytest.mark.parametrize("code,what", [
    ("import socket\nsocket.create_connection(('1.1.1.1', 80), timeout=3)", "socket"),
    ("import urllib.request\nurllib.request.urlopen('http://example.com')", "urllib.request"),
    ("import subprocess\nsubprocess.run(['id'])", "subprocess"),
    ("import os\nos.system('echo pwned')", "os.system"),
    ("import ctypes", "ctypes"),
    ("__import__('_posixsubprocess' if __import__('os').name != 'nt' else '_winapi')", "import"),
    ("print(open(VICTIM).read())", "reading"),
    ("import os\nprint(os.listdir(os.path.dirname(os.getcwd())))", "listing"),
    ("open('../escape.txt', 'w').write('x')", "writing"),
    ("import os\nos.remove('../victim.txt')", "os.remove"),
    ("import os\nos.execv('/bin/sh', ['sh'])", "os.exec"),
])
def test_escape_attempts_are_blocked(tmp_path, code, what):
    (tmp_path / "victim.txt").write_text("keep")
    r = run_code(tmp_path, f"VICTIM = {str(tmp_path / 'victim.txt')!r}\n" + code)
    assert r.exit_code != 0
    assert "sandbox:" in r.stderr, r.stderr
    assert (tmp_path / "victim.txt").read_text() == "keep"
    assert not (tmp_path / "escape.txt").exists()


def test_work_folder_is_a_throwaway_copy(tmp_path):
    r = run_code(tmp_path, "open('main.py', 'w').write('changed')\nopen('new.txt', 'w').write('x')")
    assert r.exit_code == 0, r.stderr
    assert (tmp_path / "w" / "main.py").read_text().startswith("open(")
    assert not (tmp_path / "w" / "new.txt").exists()


def test_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    r = run_code(tmp_path, "import os\nprint(os.environ.get('ANTHROPIC_API_KEY'))")
    assert r.stdout.strip() == "None"


def test_timeout_kills(tmp_path):
    r = run_code(tmp_path, "while True: pass", timeout_s=2)
    assert r.timed_out and r.exit_code == -1 and r.duration_s < 10


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimit check")
def test_memory_limit(tmp_path):
    r = run_code(tmp_path, "x = bytearray(1024 * 1024 * 1024)\nprint('allocated')", memory_mb=128)
    assert r.exit_code != 0 and "allocated" not in r.stdout


def test_refuses_what_needs_docker(tmp_path):
    sb = ProcessSandbox(workroot=tmp_path)
    with pytest.raises(SandboxUnavailable, match="network"):
        sb.run(SandboxSpec(image=IMG, command=["python", "-c", "1"], network="bridge"))
    with pytest.raises(SandboxUnavailable, match="needs Docker"):
        sb.run(SandboxSpec(image="alpine:3.20", command=["sh", "-c", "id"]))


def test_only_allowed_connect_target(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept()[0].sendall(b"ok"), daemon=True).start()
    code = ("import socket,sys\ns=socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=5)\n"
            "print(s.recv(2).decode())\ntry:\n socket.create_connection(('127.0.0.1', 1), timeout=2)\n"
            "except PermissionError as e:\n print('blocked', e)\n")
    work = tmp_path / "w"
    work.mkdir()
    (work / "main.py").write_text(code)
    r = ProcessSandbox(workroot=tmp_path).run(SandboxSpec(image=IMG, command=["python", "/work/main.py", str(port)],
                                                          workdir=str(work), allow_connect=("127.0.0.1", port)))
    srv.close()
    assert r.exit_code == 0, r.stderr
    assert r.stdout.splitlines()[0] == "ok" and "blocked" in r.stdout


def test_auto_mode_falls_back_but_not_for_raw_exec(tmp_path):
    auto = AutoSandbox(allowed_images=(IMG,), workroot=tmp_path, mode="auto", docker=NO_DOCKER)
    assert auto.isolation == "process" and auto.available()[0]
    r = auto.run(SandboxSpec(image=IMG, command=["python", "-c", "print(1)"]))
    assert r.stdout.strip() == "1"
    raw = AutoSandbox(allowed_images=(IMG,), mode="auto", allow_process=False, docker=NO_DOCKER)
    assert not raw.available()[0]
    with pytest.raises(SandboxUnavailable):
        raw.run(SandboxSpec(image=IMG, command=["python", "-c", "print(1)"]))
    strict = AutoSandbox(allowed_images=(IMG,), mode="docker", docker=NO_DOCKER)
    with pytest.raises(SandboxUnavailable):
        strict.run(SandboxSpec(image=IMG, command=["python", "-c", "print(1)"]))


def test_skill_lifecycle_without_docker(tmp_path):
    ctl = SecurityController(tmp_path / "s")
    sb = AutoSandbox(allowed_images=(IMG,), mode="auto", docker=NO_DOCKER)
    skm = SkillManager(ctl, tmp_path / "skills", sb)
    c = TestClient(create_app(ctl, NO_DOCKER, memory=MemoryStore(tmp_path / "m.db"), skills=skm))
    adm = {"Authorization": f"Bearer {ctl.admin_token()}"}
    tok = c.post("/admin/agents", json={"agent_id": "dev", "zones": ["standard"]}, headers=adm).json()["token"]
    ag = {"Authorization": f"Bearer {tok}"}
    files = {p.name: p.read_text() for p in EX.iterdir() if p.is_file()}
    rep = c.post("/v1/skills/submit", json={"files": files}, headers=ag).json()
    assert rep["passed"], {k: v for k, v in rep["checks"].items() if not v["ok"]}
    v = c.post("/v1/skills/text-stats/1.0.0/register", json={}, headers=ag).json()
    assert v["effect"] == "pending_approval"  # human approval still required
    c.post(f"/admin/approvals/{v['approval_id']}", json={"approve": True}, headers=adm)
    assert c.post("/v1/skills/text-stats/1.0.0/register", json={"approval_id": v["approval_id"]}, headers=ag).json()["allowed"]
    out = c.post("/v1/skills/text-stats/run", json={"inputs": {"text": "Red fox. Red dog.", "top": 1}}, headers=ag).json()
    assert out["result"]["output"]["top_terms"] == [["red", 2]]
    st = c.get("/admin/status", headers=adm).json()["sandbox"]
    assert not st["available"] and st["skills"]["available"] and st["skills"]["isolation"] == "process"


@pytest.mark.parametrize("code", [
    # rebinding library functions or builtins the guard might rely on
    "import os, posixpath, ntpath, builtins\nfor m in (posixpath, ntpath):\n m.realpath = m.abspath = m.normcase = lambda p: os.getcwd()\n"
    "builtins.any = lambda x: True\nbuiltins.isinstance = lambda *a: True\nprint(open(VICTIM).read())",
    # a path object that shows the check one path and the open call another
    "import os\nclass P:\n n = 0\n def __fspath__(self):\n  P.n += 1\n  return 'main.py' if P.n == 1 else VICTIM\nprint(open(P()).read())",
    # str subclass with a custom __eq__ for a blocked import
    "class S(str):\n def __eq__(s, o): return False\n __hash__ = str.__hash__\n__import__(S('ctypes'))",
    # editing the guard's closures through a traceback
    "try:\n open(VICTIM)\nexcept PermissionError as e:\n t = e.__traceback__\n while t.tb_next: t = t.tb_next\n f = t.tb_frame\n"
    " print(open(VICTIM).read())",
    # reaching the hook through the garbage collector or a thread
    "import gc\nprint(gc.get_objects())",
    "import _thread\n_thread.start_new_thread(lambda: None, ())",
    # symlink out of the work folder
    "import os\nos.symlink(VICTIM, 'link')\nprint(open('link').read())",
])
def test_guard_resists_tampering(tmp_path, code):
    (tmp_path / "victim.txt").write_text("keep")
    r = run_code(tmp_path, f"VICTIM = {str(tmp_path / 'victim.txt')!r}\n" + code)
    assert "keep" not in r.stdout, (r.stdout, r.stderr)
    if "__fspath__" not in code:  # that one may simply open main.py: either way the victim is never read
        assert r.exit_code != 0 and "sandbox:" in r.stderr, r.stderr
