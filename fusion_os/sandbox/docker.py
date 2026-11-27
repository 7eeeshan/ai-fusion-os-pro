"""Isolated command execution in a locked-down Docker container.

Defaults: no network, read-only root filesystem, all Linux capabilities dropped, no-new-privileges, unprivileged
user, PID/memory/CPU limits, small noexec /tmp, wall-clock timeout (container is killed on timeout). Only images on
the allowlist may run. There is deliberately no fallback to running on the host: if Docker is not available the
sandbox refuses (fail closed).
"""
from __future__ import annotations

import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_IMAGES = ("python:3.12-slim", "alpine:3.20")
NETWORK_MODES = ("none", "bridge")
_NAME_OK = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/@-]*$")


class SandboxUnavailable(RuntimeError):
    pass


class SandboxError(ValueError):
    pass


@dataclass
class SandboxSpec:
    image: str
    command: list[str]
    network: str = "none"
    timeout_s: float = 60
    memory_mb: int = 512
    cpus: float = 1.0
    pids: int = 128
    workdir: Optional[str] = None  # host folder mounted at /work
    workdir_writable: bool = False
    env: dict[str, str] = field(default_factory=dict)
    stdin: Optional[str] = None


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    container: str
    argv: list[str]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class DockerSandbox:
    def __init__(self, allowed_images: tuple[str, ...] | list[str] = DEFAULT_IMAGES, docker_bin: Optional[str] = None,
                 workroot: Optional[Path] = None, max_output: int = 1_000_000):
        self.allowed_images = tuple(allowed_images)
        self.docker = docker_bin or shutil.which("docker")
        self.workroot = workroot.resolve() if workroot else None
        self.max_output = max_output

    def available(self) -> tuple[bool, str]:
        if not self.docker:
            return False, "docker CLI not found"
        try:
            r = subprocess.run([self.docker, "info", "--format", "{{.ServerVersion}}"], capture_output=True,
                               text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"docker not reachable: {exc}"
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:300] or "docker daemon not running"
        return True, r.stdout.strip()

    def build_argv(self, spec: SandboxSpec, name: str) -> list[str]:
        if spec.image not in self.allowed_images:
            raise SandboxError(f"image {spec.image!r} is not on the sandbox allowlist")
        if spec.network not in NETWORK_MODES:
            raise SandboxError(f"network must be one of {NETWORK_MODES}")
        if not spec.command:
            raise SandboxError("command is empty")
        if not (1 <= spec.timeout_s <= 3600 and 32 <= spec.memory_mb <= 16384 and 0.1 <= spec.cpus <= 16
                and 8 <= spec.pids <= 4096):
            raise SandboxError("resource limits out of range")
        argv = [
            self.docker or "docker", "run", "--rm", "--name", name,
            "--network", spec.network,
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(spec.pids),
            "--memory", f"{spec.memory_mb}m", "--memory-swap", f"{spec.memory_mb}m",
            "--cpus", str(spec.cpus),
            "--user", "65534:65534",
            "--ipc", "none",
            "--init",
        ]
        if spec.stdin is not None:
            argv.append("-i")
        for k, v in spec.env.items():
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", k):
                raise SandboxError(f"bad env var name {k!r}")
            argv += ["-e", f"{k}={v}"]
        if spec.workdir:
            host = Path(spec.workdir).resolve()
            if self.workroot is None or not host.is_relative_to(self.workroot):
                raise SandboxError("workdir must be inside the sandbox work root")
            host.mkdir(parents=True, exist_ok=True)
            mode = "rw" if spec.workdir_writable else "ro"
            argv += ["-v", f"{host}:/work:{mode}", "-w", "/work"]
        argv.append(spec.image)
        argv += list(spec.command)
        return argv

    def run(self, spec: SandboxSpec) -> SandboxResult:
        ok, why = self.available()
        if not ok:
            raise SandboxUnavailable(f"sandbox unavailable, refusing to run on the host: {why}")
        name = "fos-sbx-" + secrets.token_hex(6)
        argv = self.build_argv(spec, name)
        t0 = time.monotonic()
        timed_out = False
        try:
            p = subprocess.run(argv, input=spec.stdin, capture_output=True, text=True, timeout=spec.timeout_s,
                               errors="replace")
            code, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            subprocess.run([self.docker, "kill", name], capture_output=True, timeout=30)
            code = -1
            out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = "timed out"
        return SandboxResult(code, out[: self.max_output], err[: self.max_output], time.monotonic() - t0,
                             timed_out, name, argv)
