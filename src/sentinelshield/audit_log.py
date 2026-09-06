from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from sentinelshield.violation_event_bridge import ViolationEvent


class AuditLog:
    """Append-only JSON Lines audit log."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, event: ViolationEvent) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(
                json.dumps(
                    asdict(event),
                    sort_keys=True,
                )
                + "\n"
            )

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []

        records = []

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            for line in handle:
                line = line.strip()

                if line:
                    records.append(
                        json.loads(line)
                    )

        return records
