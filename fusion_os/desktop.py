"""Desktop backend: what the Windows app's shell starts (`python -m fusion_os desktop`).

- one instance per user: an exclusive lock file; a second start reports the running one and exits;
- defaults for a PC without Docker: process sandbox fallback, native Tor, in-process worker and scheduler, missions
  interrupted by a crash or reboot are marked so they can be resumed;
- settings from <data>/desktop.env (only known keys), so nobody edits environment variables by hand;
- links to AI Fusion Engine Pro automatically when its API token is found;
- first run migrates (copies, never moves) data from the Claude app's redirected AppData if that is where an earlier
  manual install kept it;
- no admin-token pasting: each start writes a random launch secret to <data>/security/desktop.json (readable by
  this Windows user only, like the admin token). The shell opens /dashboard#launch=<secret> and the dashboard
  exchanges it for a session on the loopback API. The API only listens on 127.0.0.1.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Optional

from . import paths

SETTINGS_KEYS = ("ANTHROPIC_API_KEY", "BRAVE_API_KEY", "GITHUB_TOKEN", "AFE_URL", "AFE_TOKEN", "AFE_HOME")
SETTINGS_PREFIX = "FUSION_OS_"
SETTINGS_BLOCKED = ("FUSION_OS_HOME",)  # decided before settings are read
DEFAULTS = {
    "FUSION_OS_SANDBOX": "auto",
    "FUSION_OS_TOR": "auto",
    "FUSION_OS_WORKER": "1",
    "FUSION_OS_SCHEDULER": "1",
    "FUSION_OS_LOCATION": "local",
    "FUSION_OS_CAPABILITIES": "local-engine",
    "FUSION_OS_LLM_ORDER": "engine,queue,anthropic",
}
ENV_TEMPLATE = """# AI Fusion OS Pro desktop settings. One KEY=VALUE per line; restart the app after editing.
# Only FUSION_OS_* keys and the keys below are read. Leave a value empty to use the default.
# ANTHROPIC_API_KEY=
# BRAVE_API_KEY=
# AFE_URL=http://127.0.0.1:8765
# FUSION_OS_ENGINE_MODEL=
# FUSION_OS_LLM_ORDER=engine,queue,anthropic
# FUSION_OS_WORKSPACE=
# FUSION_OS_SANDBOX=auto        (auto: Docker when running, otherwise process isolation; docker: Docker only)
# FUSION_OS_PROCESS_EXEC=0      (1 lets raw agent commands use process isolation; weaker than Docker)
"""


class AlreadyRunning(RuntimeError):
    def __init__(self, info: dict):
        super().__init__(f"AI Fusion OS Pro is already running on port {info.get('port')}")
        self.info = info


# ---------- settings ----------
def read_settings(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if not v or k in SETTINGS_BLOCKED:
            continue
        if k in SETTINGS_KEYS or k.startswith(SETTINGS_PREFIX):
            out[k] = v
    return out


def apply_environment(home: Path, environ: Optional[dict] = None) -> dict[str, str]:
    """Defaults < desktop.env < variables already set by the person. Returns what was applied."""
    env = os.environ if environ is None else environ
    settings_file = home / "desktop.env"
    if not settings_file.exists():
        paths.write_private(settings_file, ENV_TEMPLATE)
    applied: dict[str, str] = {}
    for k, v in {**DEFAULTS, **read_settings(settings_file)}.items():
        if k not in env:
            env[k] = v
            applied[k] = v
    if "FUSION_OS_WORKSPACE" not in env:
        ws = home / "workspace"
        ws.mkdir(parents=True, exist_ok=True)
        env["FUSION_OS_WORKSPACE"] = applied["FUSION_OS_WORKSPACE"] = str(ws)
    if not env.get("AFE_TOKEN"):
        tok = find_engine_token(env)
        if tok:
            env["AFE_TOKEN"] = tok
            applied["AFE_TOKEN"] = "(found)"
    return applied


def _local_appdata_candidates(env: dict) -> list[Path]:
    """%LOCALAPPDATA% and the Claude app's redirected copy of it (where earlier manual installs ended up)."""
    out = []
    lad = env.get("LOCALAPPDATA")
    if lad:
        base = Path(lad)
        out.append(base)
        pk = base / "Packages"
        if pk.is_dir():
            out += sorted(p / "LocalCache" / "Local" for p in pk.glob("Claude_*") if (p / "LocalCache" / "Local").is_dir())
    return out


def find_engine_token(env: dict) -> Optional[str]:
    dirs = [Path(env["AFE_HOME"])] if env.get("AFE_HOME") else []
    dirs += [d / "AIFusionEnginePro" for d in _local_appdata_candidates(env)]
    for d in dirs:
        f = d / "api_token"
        try:
            t = f.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if t:
            return t
    return None


# ---------- migration ----------
def migrate_legacy_data(home: Path, env: Optional[dict] = None) -> Optional[Path]:
    """Copy data from an earlier install kept in the Claude app's redirected AppData, once, if this home has none.
    The source is only read, never changed."""
    env = os.environ if env is None else env
    if (home / "security").exists():
        return None
    for base in _local_appdata_candidates(env)[1:]:
        src = base / "AIFusionOSPro"
        if (src / "security").is_dir() and src.resolve() != home.resolve():
            home.mkdir(parents=True, exist_ok=True)
            for item in src.iterdir():
                dst = home / item.name
                if item.name in ("desktop.lock", "desktop.json") or dst.exists():
                    continue
                if item.is_dir():
                    shutil.copytree(item, dst, symlinks=False)
                else:
                    shutil.copy2(item, dst)
            (home / "migrated_from.txt").write_text(f"{src}\ncopied {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
                                                    encoding="utf-8")
            return src
    return None


# ---------- single instance ----------
class InstanceLock:
    def __init__(self, path: Path):
        self.path = path
        self.fh = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            self.fh = None
            return False
        return True

    def release(self) -> None:
        if self.fh is not None:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            self.fh.close()
            self.fh = None


def pick_port(preferred: int, host: str = "127.0.0.1") -> int:
    for port in (preferred, 0):
        with socket.socket() as s:
            if os.name != "nt":  # match uvicorn, so a restart after a crash gets the same port despite TIME_WAIT
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
            except OSError:
                continue
            return s.getsockname()[1]
    raise OSError("no free port")


def info_path() -> Path:
    return paths.security_dir() / "desktop.json"


def read_info() -> Optional[dict]:
    try:
        return json.loads(info_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class DesktopSession:
    """State the API needs in desktop mode: the launch secret and a way to stop the server."""

    def __init__(self, secret: str):
        self.secret = secret
        self.stop_requested = False
        self.server = None

    def check(self, candidate: str) -> bool:
        return bool(candidate) and hmac.compare_digest(candidate.encode(), self.secret.encode())

    def request_stop(self) -> None:
        self.stop_requested = True
        if self.server is not None:
            self.server.should_exit = True


def stop_running(wait_s: float = 20) -> bool:
    """Ask a running desktop backend to shut down (used by the installer before an upgrade or uninstall)."""
    import httpx
    info = read_info()
    if not info:
        return False
    try:
        httpx.post(f"http://127.0.0.1:{info['port']}/desktop/shutdown", json={"launch": info["launch"]}, timeout=5)
    except httpx.HTTPError:
        return False
    t0 = time.monotonic()
    while time.monotonic() - t0 < wait_s and info_path().exists():
        time.sleep(0.25)
    return not info_path().exists()


def run(port: int = 8790, open_browser: bool = False) -> int:
    home = paths.home()
    src = migrate_legacy_data(home)
    applied = apply_environment(home)
    lock = InstanceLock(home / "desktop.lock")
    if not lock.acquire():
        info = read_info() or {}
        print(json.dumps({"already_running": True, "port": info.get("port"), "pid": info.get("pid")}))
        return 3
    try:
        import uvicorn
        from .api.server import create_app
        port = pick_port(port)
        session = DesktopSession(secrets.token_urlsafe(32))
        paths.write_private(info_path(), json.dumps({"pid": os.getpid(), "port": port, "launch": session.secret,
                                                     "started": time.time(), "home": str(home)}))
        os.environ["FUSION_OS_DESKTOP"] = "1"
        app = create_app(desktop=session)
        cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
        server = uvicorn.Server(cfg)
        session.server = server
        print(json.dumps({"ready_on": port, "migrated_from": str(src) if src else None,
                          "settings": sorted(k for k in applied if not k.endswith(("KEY", "TOKEN")))}), flush=True)
        if open_browser:
            import webbrowser
            webbrowser.open(f"http://127.0.0.1:{port}/dashboard#launch={session.secret}")
        server.run()
        return 0
    finally:
        try:
            info_path().unlink()
        except OSError:
            pass
        lock.release()


if __name__ == "__main__":
    sys.exit(run())
