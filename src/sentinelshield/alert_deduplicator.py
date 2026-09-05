from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sentinelshield.alert_dispatcher import Alert


@dataclass(frozen=True)
class DeduplicationResult:
    allowed: bool
    reason: str


class AlertDeduplicator:
    """
    Prevents duplicate alerts during a configurable cooldown period.

    Deduplication key:
        project + event_type + reason
    """

    def __init__(self, cooldown_seconds: int = 300):
        if not isinstance(cooldown_seconds, int):
            raise TypeError("cooldown_seconds must be int")

        if cooldown_seconds < 0:
            raise ValueError(
                "cooldown_seconds must be >= 0"
            )

        self.cooldown = timedelta(
            seconds=cooldown_seconds
        )

        self._last_alert: dict[
            tuple[str, str, str],
            datetime,
        ] = {}

    def _key(
        self,
        alert: Alert,
    ) -> tuple[str, str, str]:
        return (
            alert.project,
            alert.event_type.value,
            alert.reason,
        )

    def allow(
        self,
        alert: Alert,
        *,
        now: datetime | None = None,
    ) -> DeduplicationResult:

        if not isinstance(alert, Alert):
            raise TypeError("alert must be Alert")

        if now is None:
            now = datetime.now(timezone.utc)

        if now.tzinfo is None:
            raise ValueError(
                "now must be timezone-aware"
            )

        key = self._key(alert)
        previous = self._last_alert.get(key)

        if previous is None:
            self._last_alert[key] = now
            return DeduplicationResult(
                allowed=True,
                reason="NEW_ALERT",
            )

        elapsed = now - previous

        if elapsed >= self.cooldown:
            self._last_alert[key] = now

            return DeduplicationResult(
                allowed=True,
                reason="COOLDOWN_EXPIRED",
            )

        return DeduplicationResult(
            allowed=False,
            reason="DUPLICATE_SUPPRESSED",
        )

    def reset(self) -> None:
        self._last_alert.clear()

    def size(self) -> int:
        return len(self._last_alert)
