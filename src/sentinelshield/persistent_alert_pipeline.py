from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sentinelshield.alert_deduplicator import AlertDeduplicator
from sentinelshield.alert_dispatcher import Alert
from sentinelshield.alert_store import AlertStore


@dataclass(frozen=True)
class PersistentAlertResult:
    stored: bool
    suppressed: bool
    reason: str
    alert: Alert


class PersistentAlertPipeline:
    """
    Deduplicates alerts before persisting them.
    """

    def __init__(
        self,
        store: AlertStore,
        deduplicator: AlertDeduplicator | None = None,
    ):
        self.store = store
        self.deduplicator = (
            deduplicator or AlertDeduplicator()
        )

    def process(
        self,
        alert: Alert,
        *,
        now: datetime | None = None,
    ) -> PersistentAlertResult:

        decision = self.deduplicator.allow(
            alert,
            now=now,
        )

        if not decision.allowed:
            return PersistentAlertResult(
                stored=False,
                suppressed=True,
                reason=decision.reason,
                alert=alert,
            )

        self.store.save(alert)

        return PersistentAlertResult(
            stored=True,
            suppressed=False,
            reason=decision.reason,
            alert=alert,
        )

    def count(self) -> int:
        return self.store.count()
