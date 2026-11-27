"""Per-mission resource budgets: calls, compute seconds, money. Exceeding any limit denies further actions."""
from __future__ import annotations

from typing import Optional

from .store import Store

DEFAULT_LIMITS = {"max_calls": 500, "max_seconds": 3600.0, "max_usd": 5.0}


class Budgets:
    def __init__(self, store: Store):
        self.store = store

    def set(self, mission_id: str, max_calls: int, max_seconds: float, max_usd: float) -> None:
        self.store.execute(
            "INSERT INTO budgets(mission_id, max_calls, max_seconds, max_usd) VALUES (?,?,?,?) "
            "ON CONFLICT(mission_id) DO UPDATE SET max_calls=excluded.max_calls, max_seconds=excluded.max_seconds, "
            "max_usd=excluded.max_usd",
            (mission_id, max_calls, max_seconds, max_usd),
        )

    def get(self, mission_id: str) -> Optional[dict]:
        rows = self.store.query("SELECT * FROM budgets WHERE mission_id=?", (mission_id,))
        return dict(rows[0]) if rows else None

    def list(self) -> list[dict]:
        return [dict(r) for r in self.store.query("SELECT * FROM budgets ORDER BY mission_id")]

    def check(self, mission_id: str, calls: int, seconds: float, usd: float) -> tuple[bool, str]:
        b = self.get(mission_id)
        if b is None:
            self.set(mission_id, **DEFAULT_LIMITS)
            b = self.get(mission_id)
        assert b is not None
        if b["used_calls"] + calls > b["max_calls"]:
            return False, "mission call budget exceeded"
        if b["used_seconds"] + seconds > b["max_seconds"]:
            return False, "mission compute-time budget exceeded"
        if b["used_usd"] + usd > b["max_usd"]:
            return False, "mission spending budget exceeded"
        return True, "within budget"

    def record(self, mission_id: str, calls: int, seconds: float, usd: float) -> None:
        self.store.execute(
            "UPDATE budgets SET used_calls=used_calls+?, used_seconds=used_seconds+?, used_usd=used_usd+? "
            "WHERE mission_id=?",
            (calls, seconds, usd, mission_id),
        )
