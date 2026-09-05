from __future__ import annotations

from datetime import datetime

from sentinelshield.alert_store import AlertStore
from sentinelshield.persistent_alert_pipeline import (
    PersistentAlertPipeline,
)
from sentinelshield.alert_deduplicator import AlertDeduplicator
from sentinelshield.live_event_pipeline import LiveEventPipeline


class ProductionAlertPipeline:
    """
    Full SentinelShield alert path:

    Live Event
        -> Alert
        -> Deduplication
        -> Persistent Store
    """

    def __init__(
        self,
        live_event_pipeline: LiveEventPipeline,
        alert_store: AlertStore,
        cooldown_seconds: int = 300,
    ):
        self.live_event_pipeline = live_event_pipeline

        self.alert_pipeline = PersistentAlertPipeline(
            store=alert_store,
            deduplicator=AlertDeduplicator(
                cooldown_seconds=cooldown_seconds
            ),
        )

    def run_once(
        self,
        *,
        project: str,
        path: str,
        now: datetime | None = None,
    ):
        result = self.live_event_pipeline.run_once(
            project=project,
            path=path,
        )

        if not result.alert_created:
            return result, None

        persisted = self.alert_pipeline.process(
            result.alert,
            now=now,
        )

        return result, persisted
