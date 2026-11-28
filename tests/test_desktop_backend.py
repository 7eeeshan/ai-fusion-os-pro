import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from fusion_os import desktop
from fusion_os.api.server import create_app
from fusion_os.sandbox import DockerSandbox
from fusion_os.security.controller import SecurityController


def test_settings_only_known_keys(tmp_path):
    f = tmp_path / "desktop.env"
    f.write_text("# c\nANTHROPIC_API_KEY=sk-1\nFUSION_OS_ENGINE_MODEL='m'\nPATH=/evil\nFUSION_OS_HOME=/x\nEMPTY=\n"
                 "FUSION_OS_LLM_ORDER=\n")
    assert desktop.read_settings(f) == {"ANTHROPIC_API_KEY": "sk-1", "FUSION_OS_ENGINE_MODEL": "m"}


def test_apply_environment_defaults_and_engine_token(tmp_path):
    lad = tmp_path / "lad"
    (lad / "AIFusionEnginePro").mkdir(parents=True)
    (lad / "AIFusionEnginePro" / "api_token").write_text("afe-tok\n")
    home = tmp_path / "home"
    home.mkdir()
    (home / "desktop.env").write_text("FUSION_OS_SANDBOX=docker\n")
    env = {"LOCALAPPDATA": str(lad), "FUSION_OS_TOR": "docker"}
    desktop.apply_environment(home, env)
    assert env["FUSION_OS_SANDBOX"] == "docker"       # settings file beats defaults
    assert env["FUSION_OS_TOR"] == "docker"           # variables already set beat the settings file
    assert env["FUSION_OS_WORKER"] == "1" and env["AFE_TOKEN"] == "afe-tok"
    assert Path(env["FUSION_OS_WORKSPACE"]).is_dir()


def test_migrates_from_claude_redirected_appdata_without_touching_source(tmp_path):
    lad = tmp_path / "Local"
    src = lad / "Packages" / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "Local" / "AIFusionOSPro"
    (src / "security").mkdir(parents=True)
    (src / "security" / "admin_token").write_text("old-admin")
    (src / "memory.db").write_text("mem")
    (src / "desktop.lock").write_text("")
    before = sorted(p.relative_to(src).as_posix() for p in src.rglob("*"))
    home = lad / "AIFusionOSPro"
    assert desktop.migrate_legacy_data(home, {"LOCALAPPDATA": str(lad)}) == src
    assert (home / "security" / "admin_token").read_text() == "old-admin" and (home / "memory.db").exists()
    assert not (home / "desktop.lock").exists() and (home / "migrated_from.txt").exists()
    assert sorted(p.relative_to(src).as_posix() for p in src.rglob("*")) == before
    (src / "memory.db").write_text("newer")
    assert desktop.migrate_legacy_data(home, {"LOCALAPPDATA": str(lad)}) is None  # only once
    assert (home / "memory.db").read_text() == "mem"


def test_copies_engine_data_once_without_touching_source(tmp_path):
    lad = tmp_path / "Local"
    src = lad / "Packages" / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "Local" / "AIFusionEnginePro"
    (src / "models").mkdir(parents=True)
    (src / "logs").mkdir()
    (src / "config.json").write_text("{}")
    (src / "api_token").write_text("tok")
    (src / "models" / "m.gguf").write_text("weights")
    (src / "logs" / "a.log").write_text("x")
    before = sorted(p.relative_to(src).as_posix() for p in src.rglob("*"))
    env = {"LOCALAPPDATA": str(lad)}
    assert desktop.migrate_engine_data(env) == src
    dst = lad / "AIFusionEnginePro"
    assert (dst / "api_token").read_text() == "tok" and (dst / "models" / "m.gguf").exists()
    assert not (dst / "logs").exists() and not (lad / "AIFusionEnginePro.copying").exists()
    assert sorted(p.relative_to(src).as_posix() for p in src.rglob("*")) == before
    (src / "api_token").write_text("newer")
    assert desktop.migrate_engine_data(env) is None  # only once
    assert (dst / "api_token").read_text() == "tok"
    assert desktop.migrate_engine_data({**env, "AFE_HOME": str(tmp_path / "x")}) is None


def test_engine_link_finds_token_written_later(tmp_path, monkeypatch):
    from fusion_os.engine_link import EngineLink
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.delenv("AFE_TOKEN", raising=False)
    monkeypatch.delenv("AFE_HOME", raising=False)
    link = EngineLink()
    assert link._headers() == {}
    (tmp_path / "AIFusionEnginePro").mkdir()
    (tmp_path / "AIFusionEnginePro" / "api_token").write_text("late\n")
    assert link._headers() == {"Authorization": "Bearer late"}
    assert EngineLink(token="")._headers() == {}


def test_instance_lock(tmp_path):
    a, b = desktop.InstanceLock(tmp_path / "l"), desktop.InstanceLock(tmp_path / "l")
    assert a.acquire()
    # flock locks are per open file, so a second handle in the same process is refused like another process
    assert not b.acquire()
    a.release()
    assert b.acquire()
    b.release()


def test_desktop_session_endpoint(tmp_path):
    ctl = SecurityController(tmp_path / "s")
    sess = desktop.DesktopSession("launch-secret")
    c = TestClient(create_app(ctl, DockerSandbox(docker_bin="/nope"), desktop=sess))
    assert c.post("/desktop/session", json={"launch": "wrong"}).status_code == 403
    assert c.post("/desktop/session", json={"launch": "launch-secret"}).json()["admin_token"] == ctl.admin_token()
    assert c.post("/desktop/shutdown", json={"launch": "x"}).status_code == 403
    assert c.post("/desktop/shutdown", json={"launch": "launch-secret"}).json()["ok"] and sess.stop_requested
    plain = TestClient(create_app(ctl, DockerSandbox(docker_bin="/nope")))
    assert plain.post("/desktop/session", json={"launch": "launch-secret"}).status_code == 404


def test_desktop_backend_end_to_end(tmp_path):
    home = tmp_path / "home"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FUSION_OS_", "AFE_"))}
    env.update({"FUSION_OS_HOME": str(home), "LOCALAPPDATA": str(tmp_path / "lad"), "FUSION_OS_LLM_ORDER": "anthropic"})
    p = subprocess.Popen([sys.executable, "-m", "fusion_os", "desktop", "--port", "0"], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready = json.loads(p.stdout.readline())
        port = ready["ready_on"]
        info = json.loads((home / "security" / "desktop.json").read_text())
        assert info["port"] == port
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                if httpx.get(base + "/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        tok = httpx.post(base + "/desktop/session", json={"launch": info["launch"]}).json()["admin_token"]
        st = httpx.get(base + "/admin/status", headers={"Authorization": f"Bearer {tok}"}).json()
        assert st["sandbox"]["skills"]["available"]  # Docker or the process fallback
        second = subprocess.run([sys.executable, "-m", "fusion_os", "desktop", "--port", "0"], env=env,
                                capture_output=True, text=True, timeout=60)
        assert second.returncode == 3 and json.loads(second.stdout)["port"] == port
        stop = subprocess.run([sys.executable, "-m", "fusion_os", "desktop-stop"], env=env, capture_output=True,
                              timeout=60)
        assert stop.returncode == 0, stop.stderr
        assert p.wait(30) == 0
        assert not (home / "security" / "desktop.json").exists()
    finally:
        if p.poll() is None:
            p.kill()
