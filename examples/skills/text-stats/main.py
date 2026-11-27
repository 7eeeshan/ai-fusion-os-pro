import json
import re
import sys
from collections import Counter


def analyze(text: str, top: int = 10) -> dict:
    words = re.findall(r"[A-Za-z0-9']+", text.lower())
    sentences = [s for s in re.split(r"[.!?]+", text) if s.strip()]
    return {
        "words": len(words),
        "sentences": len(sentences),
        "top_terms": Counter(w for w in words if len(w) > 2).most_common(top),
    }


if __name__ == "__main__":
    data = json.loads(sys.stdin.read() or "{}")
    print(json.dumps(analyze(str(data.get("text", "")), int(data.get("top", 10)))))
