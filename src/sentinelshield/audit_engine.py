from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditEngine:
    def __init__(self, path="runtime_data/audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, *, event, action, decision, reason, executed=False):
        if not event:
            raise ValueError("event must not be empty")
        if not action:
            raise ValueError("action must not be empty")

        entry = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event": str(event),
            "action": str(action),
            "decision": str(decision),
            "reason": str(reason),
            "executed": bool(executed),
        }

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return entry

    def read_all(self):
        if not self.path.exists():
            return []

        result = []

        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    result.append(json.loads(line))

        return result
