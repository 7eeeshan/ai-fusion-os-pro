"""Backups and restore of all state (SQLite databases via the online backup API, policy, skills, config)."""
from __future__ import annotations

import json
import sqlite3
import time
import zipfile
from pathlib import Path


class BackupManager:
    def __init__(self, home: Path, ctl, keep: int = 20):
        self.home, self.ctl, self.keep = home, ctl, keep
        self.dir = home / "backups"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _files(self) -> list[Path]:
        out = []
        for p in self.home.rglob("*"):
            if p.is_file() and self.dir not in p.parents and not p.name.endswith(("-wal", "-shm", ".tmp")) and "tor" not in p.parts:
                out.append(p)
        return out

    def create(self, label: str = "manual", by: str = "admin") -> str:
        name = time.strftime("%Y%m%d-%H%M%S") + f"-{label}.zip"
        target = self.dir / name
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
            for p in self._files():
                rel = p.relative_to(self.home).as_posix()
                if p.suffix == ".db":
                    tmp = p.with_suffix(".bak.tmp")
                    src = sqlite3.connect(str(p))
                    dst = sqlite3.connect(str(tmp))
                    src.backup(dst)
                    dst.close()
                    src.close()
                    z.write(tmp, rel)
                    tmp.unlink()
                else:
                    z.write(p, rel)
            z.writestr("BACKUP.json", json.dumps({"created": time.time(), "label": label}))
        for old in sorted(self.dir.glob("*.zip"))[:-self.keep]:
            old.unlink()
        self.ctl.audit.append(by, "backup.create", {"file": name})
        return name

    def list(self) -> list[dict]:
        return [{"name": p.name, "bytes": p.stat().st_size} for p in sorted(self.dir.glob("*.zip"), reverse=True)]

    def restore_plan(self, name: str) -> list[str]:
        p = (self.dir / name).resolve()
        if p.parent != self.dir.resolve() or not p.exists():
            raise FileNotFoundError(name)
        with zipfile.ZipFile(p) as z:
            return [n for n in z.namelist() if n != "BACKUP.json"]

    def restore(self, name: str, by: str = "admin") -> dict:
        """Restore into place after taking a safety backup. Restart the service afterwards so connections reopen."""
        members = self.restore_plan(name)
        safety = self.create("pre-restore", by)
        with zipfile.ZipFile(self.dir / name) as z:
            for m in members:
                dest = (self.home / m).resolve()
                if self.home.resolve() not in dest.parents:
                    raise ValueError(f"unsafe path in backup: {m}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.suffix == ".db" and dest.exists():
                    # Copy into the live database with SQLite's backup API: safe with open connections and WAL,
                    # and works on Windows where open files cannot be replaced.
                    tmp = dest.with_suffix(".restore.tmp")
                    tmp.write_bytes(z.read(m))
                    src = sqlite3.connect(str(tmp))
                    dst = sqlite3.connect(str(dest), timeout=30)
                    src.backup(dst)
                    dst.close()
                    src.close()
                    tmp.unlink()
                    continue
                if dest.exists():
                    dest.chmod(0o644)
                dest.write_bytes(z.read(m))
        self.ctl.audit.append(by, "backup.restore", {"file": name, "safety_backup": safety, "files": len(members)})
        return {"restored": len(members), "safety_backup": safety, "restart_required": True}
