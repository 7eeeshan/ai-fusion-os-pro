"""Learning from the person's feedback.

- A thumbs up or down on an answer is saved with the conversation up to it.
- A thumbs down with a note ("don't do X, do Y") becomes a lesson: one short rule, written by the model from the
  note (or the note itself). Lessons are shown and editable in the Improve page, and the relevant ones are added to
  the system prompt of later chats, so the assistant changes its behaviour right away.
- Good answers, and better answers the person wrote, form a training set (JSONL in chat format) for LoRA training
  of the local model. Answers that came from a cloud model (e.g. Claude, used as a fallback) are kept out of the
  training set: only the local model's own answers and the person's own words are used to train it.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Optional

from ..db import SafeConn

SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT, message_id INTEGER UNIQUE,
    rating INTEGER, note TEXT DEFAULT '', better TEXT DEFAULT '', conversation TEXT, answer TEXT, provider TEXT,
    created REAL);
CREATE TABLE IF NOT EXISTS lessons(id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT, feedback_id INTEGER,
    enabled INTEGER DEFAULT 1, uses INTEGER DEFAULT 0, created REAL);
"""
LOCAL_PROVIDERS = {"engine"}
MAX_LESSONS_IN_PROMPT = 12
LESSON_PROMPT = ("You turn a person's feedback on an assistant's answer into ONE short, general rule for the "
                 "assistant to follow in future chats (at most 30 words, imperative, no quotes, no preamble). "
                 "If the feedback is only about this one answer and there is no general rule, reply NONE.")
_WORD = re.compile(r"[a-z0-9]{3,}")


def _words(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


class LessonStore:
    def __init__(self, path: Path):
        self.db = SafeConn(path)
        self.db.executescript(SCHEMA)

    # ---------- feedback ----------
    def rate(self, chat_id: str, message_id: int, rating: int, conversation: list[dict], answer: str,
             provider: str = "", note: str = "", better: str = "") -> dict:
        rating = 1 if rating > 0 else -1
        now = time.time()
        self.db.execute(
            "INSERT INTO feedback(chat_id,message_id,rating,note,better,conversation,answer,provider,created) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(message_id) DO UPDATE SET rating=excluded.rating, "
            "note=excluded.note, better=excluded.better, created=excluded.created",
            (chat_id, message_id, rating, note[:4000], better[:20000], json.dumps(conversation[-12:]), answer[:20000],
             provider, now))
        row = self.db.execute("SELECT id FROM feedback WHERE message_id=?", (message_id,)).fetchone()
        return {"id": row["id"], "rating": rating}

    def feedback_for(self, message_id: int) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM feedback WHERE message_id=?", (message_id,)).fetchone()
        return dict(r) if r else None

    def ratings(self, chat_id: str) -> dict[int, int]:
        rows = self.db.execute("SELECT message_id, rating FROM feedback WHERE chat_id=?", (chat_id,)).fetchall()
        return {r["message_id"]: r["rating"] for r in rows}

    # ---------- lessons ----------
    def add_lesson(self, text: str, feedback_id: Optional[int] = None) -> dict:
        text = " ".join((text or "").split())[:400]
        if not text:
            raise ValueError("a lesson needs some text")
        lid = self.db.execute("INSERT INTO lessons(text,feedback_id,created) VALUES (?,?,?)",
                              (text, feedback_id, time.time())).lastrowid
        return {"id": lid, "text": text, "enabled": True}

    def lesson_from_feedback(self, llm, feedback_id: int) -> Optional[dict]:
        f = self.db.execute("SELECT * FROM feedback WHERE id=?", (feedback_id,)).fetchone()
        if not f or not (f["note"] or "").strip():
            return None
        conv = json.loads(f["conversation"] or "[]")
        question = next((m["content"] for m in reversed(conv) if m.get("role") == "user"), "")
        text = f["note"].strip()
        if llm is not None:
            try:
                out = llm.complete(LESSON_PROMPT, f"Question: {question[:1500]}\n\nAnswer: {f['answer'][:2000]}\n\n"
                                   f"Feedback: {f['note'][:1500]}", 120).strip().strip('"')
                if out.upper().startswith("NONE"):
                    return None
                if 3 < len(out) <= 400:
                    text = out
            except Exception:
                pass  # no model: keep the person's own words
        return self.add_lesson(text, feedback_id)

    def lessons(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM lessons ORDER BY id DESC").fetchall()
        return [{"id": r["id"], "text": r["text"], "enabled": bool(r["enabled"]), "uses": r["uses"],
                 "created": r["created"]} for r in rows]

    def update_lesson(self, lid: int, text: Optional[str] = None, enabled: Optional[bool] = None) -> None:
        if text is not None:
            self.db.execute("UPDATE lessons SET text=? WHERE id=?", (" ".join(text.split())[:400], lid))
        if enabled is not None:
            self.db.execute("UPDATE lessons SET enabled=? WHERE id=?", (int(enabled), lid))

    def delete_lesson(self, lid: int) -> None:
        self.db.execute("DELETE FROM lessons WHERE id=?", (lid,))

    def for_prompt(self, query: str) -> list[str]:
        """The lessons most related to this request (word overlap), then the newest, up to a limit."""
        rows = [r for r in self.lessons() if r["enabled"]]
        q = _words(query)
        rows.sort(key=lambda r: (len(q & _words(r["text"])), r["id"]), reverse=True)
        picked = rows[:MAX_LESSONS_IN_PROMPT]
        if picked:
            self.db.execute(f"UPDATE lessons SET uses=uses+1 WHERE id IN ({','.join('?' * len(picked))})",
                            [r["id"] for r in picked])
        return [r["text"] for r in picked]

    # ---------- training set ----------
    def training_examples(self, include_cloud: bool = False) -> list[dict]:
        out = []
        for f in self.db.execute("SELECT * FROM feedback ORDER BY id").fetchall():
            conv = [m for m in json.loads(f["conversation"] or "[]") if m.get("role") in ("user", "assistant")]
            if not conv or conv[-1].get("role") != "user":
                continue
            if (f["better"] or "").strip():
                answer = f["better"].strip()  # the person's own better answer: always usable
            elif f["rating"] > 0 and (include_cloud or (f["provider"] or "") in LOCAL_PROVIDERS):
                answer = f["answer"]
            else:
                continue
            out.append({"messages": conv + [{"role": "assistant", "content": answer}]})
        return out

    def stats(self) -> dict:
        r = self.db.execute("SELECT SUM(rating>0) up, SUM(rating<0) down, COUNT(*) n FROM feedback").fetchone()
        return {"up": r["up"] or 0, "down": r["down"] or 0, "rated": r["n"] or 0,
                "lessons": len([x for x in self.lessons() if x["enabled"]]),
                "training_examples": len(self.training_examples())}

    def export_jsonl(self, path: Path) -> int:
        ex = self.training_examples()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for e in ex:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        return len(ex)
