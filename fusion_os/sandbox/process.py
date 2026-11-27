"""Process sandbox: runs Python code without Docker, for the desktop app.

It is weaker than the Docker sandbox and only used where Docker is not available. What it enforces:
- only Python, with the app's own interpreter in isolated mode (-I -B); other images need Docker;
- networked runs are refused (they need Docker); on Linux the child also gets an empty network namespace when
  unprivileged user namespaces are available;
- the guard (guard.py) blocks sockets, child processes, native code, and file access outside the work folder and
  the Python install, through an audit hook that untrusted code cannot remove;
- the work folder is a throwaway copy unless the caller asks for it to be writable;
- a scrubbed environment (no tokens, no user profile), a private temp folder;
- OS limits: on Windows a Job Object (memory cap, one process, kill on close, no desktop/clipboard access); on
  POSIX rlimits (address space, CPU time, file size, open files) and its own process group;
- a wall-clock timeout after which the whole process tree is killed.

It does not give the kernel-level boundary that a container does. Treat it as defence in depth around code that has
already passed static analysis, not as a place to run arbitrary hostile binaries.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from .docker import DEFAULT_IMAGES, SandboxError, SandboxResult, SandboxSpec, SandboxUnavailable

PYTHON_IMAGES = ("python:3.12-slim",)
GUARD = Path(__file__).with_name("guard.py")
_PY_FLAGS = {"-I", "-B", "-u", "-s", "-E", "-S"}
_unshare_ok: Optional[bool] = None


def _linux_netns_available() -> bool:
    global _unshare_ok
    if _unshare_ok is None:
        _unshare_ok = False
        exe = shutil.which("unshare")
        if sys.platform.startswith("linux") and exe:
            try:
                _unshare_ok = subprocess.run([exe, "-rn", "true"], capture_output=True, timeout=10).returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                _unshare_ok = False
    return _unshare_ok


class ProcessSandbox:
    isolation = "process"

    def __init__(self, allowed_images: tuple[str, ...] | list[str] = DEFAULT_IMAGES, python: Optional[str] = None,
                 workroot: Optional[Path] = None, max_output: int = 1_000_000):
        self.allowed_images = tuple(allowed_images)
        # In a Windows venv, sys.executable is a launcher that starts the real interpreter as a child, which the
        # one-process job limit would refuse; the sandbox needs only the standard library, so use the base one.
        default = getattr(sys, "_base_executable", None) if os.name == "nt" else None
        self.python = python or os.environ.get("FUSION_OS_SANDBOX_PYTHON") or default or sys.executable
        self.workroot = workroot.resolve() if workroot else None
        self.max_output = max_output

    def available(self) -> tuple[bool, str]:
        if not self.python or not Path(self.python).exists():
            return False, "python interpreter for the process sandbox not found"
        extra = ", network namespace" if _linux_netns_available() else ""
        return True, f"process isolation (weaker than Docker): Python only, no network, guarded file access{extra}"

    def supports(self, spec: SandboxSpec) -> Optional[str]:
        """None if this sandbox can run the spec, otherwise the reason it needs Docker."""
        if spec.image not in PYTHON_IMAGES:
            return f"image {spec.image!r} needs Docker; the process sandbox only runs Python"
        if spec.network != "none":
            return "networked sandbox runs need Docker"
        if not spec.command or Path(spec.command[0]).name not in ("python", "python3"):
            return "the process sandbox only runs python commands"
        return None

    # ---------- command translation ----------
    def _translate(self, spec: SandboxSpec, work: Path) -> dict:
        args = list(spec.command[1:])
        while args and args[0] in _PY_FLAGS:
            args.pop(0)
        if not args:
            raise SandboxError("no script or module given")

        def fix(a: str) -> str:
            if a == "/work" or a.startswith("/work/"):
                rel = a[len("/work"):].lstrip("/")
                p = (work / rel).resolve()
                if not p.is_relative_to(work.resolve()):
                    raise SandboxError("path escapes /work")
                return str(p)
            if a.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", a) or ".." in Path(a).parts:
                raise SandboxError(f"path {a!r} is outside /work")
            return a

        if args[0] == "-m":
            if len(args) < 2 or not re.fullmatch(r"[A-Za-z_][\w.]*", args[1]):
                raise SandboxError("bad module name")
            return {"mode": "module", "target": args[1], "args": [fix(a) for a in args[2:]]}
        if args[0] == "-c":
            if len(args) < 2:
                raise SandboxError("-c needs code")
            return {"mode": "code", "target": args[1], "args": [fix(a) for a in args[2:]]}
        if args[0].startswith("-"):
            raise SandboxError(f"python option {args[0]!r} is not allowed")
        return {"mode": "script", "target": fix(args[0]), "args": [fix(a) for a in args[1:]]}

    def _env(self, tmp: Path, spec: SandboxSpec) -> dict[str, str]:
        env = {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1",
               "TMP": str(tmp), "TEMP": str(tmp), "TMPDIR": str(tmp), "HOME": str(tmp), "USERPROFILE": str(tmp),
               "PATH": ""}
        if os.name == "nt":
            env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
        for k, v in spec.env.items():
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", k):
                raise SandboxError(f"bad env var name {k!r}")
            env[k] = v
        return env

    def build_argv(self, spec: SandboxSpec, cfg_path: Path) -> list[str]:
        argv = [self.python, "-I", "-B", str(GUARD), str(cfg_path)]
        if _linux_netns_available() and not spec.allow_connect:
            argv = [shutil.which("unshare") or "unshare", "-rn"] + argv
        return argv

    # ---------- run ----------
    def run(self, spec: SandboxSpec) -> SandboxResult:
        if spec.image not in self.allowed_images:
            raise SandboxError(f"image {spec.image!r} is not on the sandbox allowlist")
        why = self.supports(spec)
        if why:
            raise SandboxUnavailable(why)
        if not (1 <= spec.timeout_s <= 3600 and 32 <= spec.memory_mb <= 16384):
            raise SandboxError("resource limits out of range")
        ok, detail = self.available()
        if not ok:
            raise SandboxUnavailable(detail)
        name = "fos-proc-" + secrets.token_hex(6)
        run_dir = Path(tempfile.mkdtemp(prefix=name + "-"))
        try:
            tmp = run_dir / "tmp"
            tmp.mkdir()
            if spec.workdir:
                host = Path(spec.workdir).resolve()
                if self.workroot is None or not host.is_relative_to(self.workroot):
                    raise SandboxError("workdir must be inside the sandbox work root")
                host.mkdir(parents=True, exist_ok=True)
                if spec.workdir_writable:
                    work = host
                else:
                    work = run_dir / "work"
                    shutil.copytree(host, work, symlinks=False,
                                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                work = run_dir / "work"
                work.mkdir()
            cfg = {"work": str(work), "tmp": str(tmp), **self._translate(spec, work)}
            if spec.allow_connect:
                cfg["allow_connect"] = [spec.allow_connect[0], int(spec.allow_connect[1])]
            cfg_path = run_dir / "guard.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            argv = self.build_argv(spec, cfg_path)
            return self._exec(argv, spec, work, tmp, name)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def _exec(self, argv: list[str], spec: SandboxSpec, work: Path, tmp: Path, name: str) -> SandboxResult:
        env = self._env(tmp, spec)
        t0 = time.monotonic()
        timed_out = False
        job = None
        kw: dict = {"cwd": str(work), "env": env, "stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
                    "stderr": subprocess.PIPE}
        if os.name == "nt":
            from . import winjob
            kw["creationflags"] = winjob.CREATE_SUSPENDED | winjob.CREATE_NO_WINDOW | winjob.BELOW_NORMAL_PRIORITY_CLASS
        else:
            kw["start_new_session"] = True
            kw["preexec_fn"] = _posix_limits(spec)
        p = subprocess.Popen(argv, **kw)
        try:
            if os.name == "nt":
                from . import winjob
                try:
                    job = winjob.confine(p, spec.memory_mb, spec.timeout_s)
                except OSError:
                    p.kill()
                    p.wait()
                    raise SandboxUnavailable("could not apply Windows job limits; refusing to run")
            try:
                out, err = p.communicate(input=(spec.stdin or "").encode("utf-8"), timeout=spec.timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill(p, job)
                out, err = p.communicate()
        finally:
            if job is not None:
                from . import winjob
                winjob.close(job)
        code = -1 if timed_out else p.returncode
        so = out.decode("utf-8", "replace")[: self.max_output]
        se = err.decode("utf-8", "replace")[: self.max_output]
        if timed_out:
            se = (se + "\ntimed out").strip()
        return SandboxResult(code, so, se, time.monotonic() - t0, timed_out, name, argv)

    @staticmethod
    def _kill(p: subprocess.Popen, job) -> None:
        if job is not None:
            from . import winjob
            winjob.terminate(job)
        elif os.name != "nt":
            import signal
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            p.kill()
        except OSError:
            pass


def _posix_limits(spec: SandboxSpec):
    mem = spec.memory_mb * 1024 * 1024
    cpu = int(spec.timeout_s) + 1

    def apply() -> None:
        import resource
        for lim, val in ((resource.RLIMIT_AS, mem), (resource.RLIMIT_CPU, cpu),
                         (resource.RLIMIT_FSIZE, 64 * 1024 * 1024), (resource.RLIMIT_NOFILE, 64),
                         (resource.RLIMIT_CORE, 0)):
            try:
                resource.setrlimit(lim, (val, val))
            except (ValueError, OSError):
                pass
    return apply
