"""Conversations for the chat interface: chats and their messages, in SQLite."""
from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any, Optional

from ..db import SafeConn

SCHEMA = """
CREATE TABLE IF NOT EXISTS chats(id TEXT PRIMARY KEY, title TEXT, created REAL, updated REAL, starred INTEGER DEFAULT 0,
                                 settings TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT, role TEXT, content TEXT,
                                    meta TEXT DEFAULT '{}', created REAL);
CREATE INDEX IF NOT EXISTS messages_chat ON messages(chat_id, id);
"""
ROLES = ("user", "assistant", "tool", "notice")


class ChatStore:
    def __init__(self, path: Path):
        self.db = SafeConn(path)
        self.db.executescript(SCHEMA)

    # ---------- chats ----------
    def create(self, title: str = "New chat", settings: Optional[dict] = None) -> dict:
        cid = "c_" + secrets.token_hex(8)
        now = time.time()
        self.db.execute("INSERT INTO chats(id,title,created,updated,settings) VALUES (?,?,?,?,?)",
                        (cid, title[:120], now, now, json.dumps(settings or {})))
        return self.get(cid)

    def get(self, cid: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM chats WHERE id=?", (cid,)).fetchone()
        return self._chat(r) if r else None

    def list(self, q: str = "", limit: int = 200) -> list[dict]:
        if q:
            like = f"%{q}%"
            rows = self.db.execute(
                "SELECT * FROM chats WHERE title LIKE ? OR id IN (SELECT chat_id FROM messages WHERE content LIKE ?) "
                "ORDER BY starred DESC, updated DESC LIMIT ?", (like, like, limit)).fetchall()
        else:
            rows = self.db.execute("SELECT * FROM chats ORDER BY starred DESC, updated DESC LIMIT ?", (limit,)).fetchall()
        return [self._chat(r) for r in rows]

    def update(self, cid: str, title: Optional[str] = None, starred: Optional[bool] = None,
               settings: Optional[dict] = None) -> Optional[dict]:
        c = self.get(cid)
        if not c:
            return None
        self.db.execute("UPDATE chats SET title=?, starred=?, settings=? WHERE id=?",
                        ((title if title is not None else c["title"])[:120],
                         int(starred if starred is not None else c["starred"]),
                         json.dumps(settings if settings is not None else c["settings"]), cid))
        return self.get(cid)

    def delete(self, cid: str) -> bool:
        self.db.execute("DELETE FROM messages WHERE chat_id=?", (cid,))
        return self.db.execute("DELETE FROM chats WHERE id=?", (cid,)).rowcount > 0

    @staticmethod
    def _chat(r) -> dict:
        return {"id": r["id"], "title": r["title"], "created": r["created"], "updated": r["updated"],
                "starred": bool(r["starred"]), "settings": json.loads(r["settings"] or "{}")}

    # ---------- messages ----------
    def add(self, cid: str, role: str, content: str, meta: Optional[dict] = None) -> dict:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        now = time.time()
        mid = self.db.execute("INSERT INTO messages(chat_id,role,content,meta,created) VALUES (?,?,?,?,?)",
                              (cid, role, content, json.dumps(meta or {}, default=str), now)).lastrowid
        self.db.execute("UPDATE chats SET updated=? WHERE id=?", (now, cid))
        return {"id": mid, "chat_id": cid, "role": role, "content": content, "meta": meta or {}, "created": now}

    def set_meta(self, mid: int, meta: dict) -> None:
        self.db.execute("UPDATE messages SET meta=? WHERE id=?", (json.dumps(meta, default=str), mid))

    def messages(self, cid: str) -> list[dict]:
        rows = self.db.execute("SELECT * FROM messages WHERE chat_id=? ORDER BY id", (cid,)).fetchall()
        return [{"id": r["id"], "chat_id": r["chat_id"], "role": r["role"], "content": r["content"],
                 "meta": json.loads(r["meta"] or "{}"), "created": r["created"]} for r in rows]

    def truncate_after(self, cid: str, mid: int) -> None:
        """Drop messages after `mid` (used to retry or edit the last turn)."""
        self.db.execute("DELETE FROM messages WHERE chat_id=? AND id>?", (cid, mid))

    def get_message(self, mid: int) -> Optional[dict[str, Any]]:
        r = self.db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        if not r:
            return None
        return {"id": r["id"], "chat_id": r["chat_id"], "role": r["role"], "content": r["content"],
                "meta": json.loads(r["meta"] or "{}"), "created": r["created"]}
