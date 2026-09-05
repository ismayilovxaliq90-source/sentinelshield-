from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from sentinelshield.alert_dispatcher import Alert
from sentinelshield.event_engine import EventSeverity, EventType


class AlertStore:
    """
    Persistent JSONL storage for SentinelShield alerts.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, alert: Alert) -> None:
        if not isinstance(alert, Alert):
            raise TypeError("alert must be Alert")

        record = asdict(alert)

        record["event_type"] = alert.event_type.value
        record["severity"] = alert.severity.value

        with self.path.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )

    def save_many(
        self,
        alerts: list[Alert] | tuple[Alert, ...],
    ) -> None:
        if not isinstance(alerts, (list, tuple)):
            raise TypeError("alerts must be list or tuple")

        for alert in alerts:
            self.save(alert)

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []

        records = []

        for line in self.path.read_text(
            encoding="utf-8"
        ).splitlines():

            if not line.strip():
                continue

            records.append(json.loads(line))

        return records

    def count(self) -> int:
        return len(self.read_all())

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()
