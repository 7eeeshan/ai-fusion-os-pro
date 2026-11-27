"""Data locations. Override with FUSION_OS_HOME."""
from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    env = os.environ.get("FUSION_OS_HOME")
    if env:
        p = Path(env)
    elif os.name == "nt":
        p = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AIFusionOSPro"
    else:
        p = Path.home() / ".fusion_os"
    p.mkdir(parents=True, exist_ok=True)
    return p


def security_dir() -> Path:
    """Security controller state. Agents never get a handle on this directory."""
    p = home() / "security"
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
