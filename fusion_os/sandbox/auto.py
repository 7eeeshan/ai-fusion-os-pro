"""Sandbox selection: Docker when it is running, otherwise the weaker process sandbox (desktop app without Docker).

FUSION_OS_SANDBOX picks the mode:
- "docker" (default for the server and cloud deployments): Docker only, refuse without it, as before;
- "auto" (the desktop app's default): Docker if it is running, otherwise the process sandbox;
- "process": always the process sandbox.

Raw agent commands (/v1/sandbox/exec) are arbitrary model-written code, so they only fall back to the process
sandbox when the operator opts in with FUSION_OS_PROCESS_EXEC=1. Skills, which pass static analysis first, do.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from .docker import DEFAULT_IMAGES, DockerSandbox, SandboxResult, SandboxSpec, SandboxUnavailable
from .process import ProcessSandbox

MODES = ("docker", "auto", "process")


class AutoSandbox:
    def __init__(self, allowed_images: tuple[str, ...] | list[str] = DEFAULT_IMAGES, workroot: Optional[Path] = None,
                 mode: Optional[str] = None, allow_process: bool = True, docker: Optional[DockerSandbox] = None,
                 process: Optional[ProcessSandbox] = None):
        self.mode = mode or os.environ.get("FUSION_OS_SANDBOX", "docker")
        if self.mode not in MODES:
            raise ValueError(f"FUSION_OS_SANDBOX must be one of {MODES}")
        self.allow_process = allow_process
        self.docker = docker or DockerSandbox(allowed_images=allowed_images, workroot=workroot)
        self.process = process or ProcessSandbox(allowed_images=allowed_images, workroot=workroot)
        self.allowed_images = tuple(allowed_images)
        self._docker_cache: tuple[float, bool, str] = (0.0, False, "")

    @property
    def workroot(self) -> Optional[Path]:
        return self.docker.workroot

    @workroot.setter
    def workroot(self, value: Optional[Path]) -> None:
        self.docker.workroot = self.process.workroot = value.resolve() if value else None

    def _docker_ok(self) -> tuple[bool, str]:
        t, ok, why = self._docker_cache
        if time.monotonic() - t > 30:
            ok, why = self.docker.available()
            self._docker_cache = (time.monotonic(), ok, why)
        return ok, why

    def _process_allowed(self) -> bool:
        return self.mode != "docker" and self.allow_process

    @property
    def isolation(self) -> str:
        if self.mode == "process":
            return "process"
        if self.mode == "auto" and not self._docker_ok()[0] and self._process_allowed():
            return "process"
        return "docker"

    def available(self) -> tuple[bool, str]:
        if self.mode != "process":
            ok, why = self._docker_ok()
            if ok:
                return True, f"docker {why}"
            if not self._process_allowed():
                return False, why
        ok, detail = self.process.available()
        return ok, detail

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if self.mode == "process":
            return self.process.run(spec)
        if self.mode == "docker" or self._docker_ok()[0]:
            return self.docker.run(spec)
        if not self.allow_process:
            raise SandboxUnavailable("Docker is not running, and raw agent commands only fall back to the process "
                                     "sandbox when FUSION_OS_PROCESS_EXEC=1")
        return self.process.run(spec)


def make_sandbox(allowed_images: tuple[str, ...] | list[str] = DEFAULT_IMAGES, workroot: Optional[Path] = None,
                 generic: bool = False) -> AutoSandbox:
    allow = not generic or os.environ.get("FUSION_OS_PROCESS_EXEC") == "1"
    return AutoSandbox(allowed_images=allowed_images, workroot=workroot, allow_process=allow)
