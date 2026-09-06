from pathlib import Path
from types import SimpleNamespace

from sentinelshield.alert_dedup_bridge import (
    AlertDedupStore,
    AlertDispatcher,
)
from sentinelshield.live_resource_enforcement import (
    LiveResourceEnforcer,
)
from sentinelshield.persistence import (
    PersistentState,
    StateStore,
)
from sentinelshield.policy_violation_detector import (
    PolicyViolationDetector,
)
from sentinelshield.recovery import (
    RecoveryManager,
)
from sentinelshield.violation_event_bridge import (
    AuditedViolationBridge,
    InMemoryAuditSink,
    ViolationEventBridge,
)


class SyntheticSampler:
    def sample(self):
        return SimpleNamespace(
            cpu_percent=99.0,
            ram_percent=99.0,
            storage_percent=99.0,
        )


class SyntheticEnforcement:
    def evaluate(
        self,
        cpu_percent,
        ram_percent,
        storage_percent,
    ):
        return SimpleNamespace(
            safe=False,
            decision=SimpleNamespace(
                value="BLOCK",
            ),
            failures=(
                "CPU",
                "RAM",
                "STORAGE",
            ),
            reason="RESOURCE_LIMIT",
        )


def build_detector():
    enforcer = LiveResourceEnforcer(
        sampler=SyntheticSampler(),
        enforcement=SyntheticEnforcement(),
    )

    return PolicyViolationDetector(
        enforcer
    )


def test_complete_pipeline(tmp_path):
    detector = build_detector()

    # 45 — violation
    violation = detector.check()

    assert violation.violated is True
    assert violation.decision == "BLOCK"

    # 46 — event + audit
    audit = InMemoryAuditSink()

    audited_bridge = AuditedViolationBridge(
        ViolationEventBridge(detector),
        audit,
    )

    event = audited_bridge.process()

    assert event is not None
    assert event.event_type == "POLICY_VIOLATION"
    assert len(audit.events) == 1

    # 47 — alert + dedup
    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    alert = dispatcher.dispatch(event)

    assert alert is not None
    assert alert.decision == "BLOCK"

    duplicate = dispatcher.dispatch(event)

    assert duplicate is None
    assert len(dispatcher.alerts) == 1

    # 48 — recovery
    recovery_calls = []

    recovery = RecoveryManager(
        detector,
        lambda: recovery_calls.append(True) or True,
    )

    recovery_result = recovery.recover()

    assert recovery_result.attempted is True
    assert recovery_result.recovered is True
    assert recovery_calls == [True]

    # 49 — persistence
    state_store = StateStore(
        tmp_path / "sentinelshield-state.json"
    )

    state = PersistentState(
        last_decision=alert.decision,
        last_reason=recovery_result.reason,
        recovery_count=1,
    )

    state_store.save(state)

    restored = StateStore(
        tmp_path / "sentinelshield-state.json"
    ).load()

    assert restored == state


def test_pipeline_does_not_modify_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    source = project / "main.py"

    original = "print('hello')\n"

    source.write_text(
        original,
        encoding="utf-8",
    )

    detector = build_detector()

    audit = InMemoryAuditSink()

    bridge = AuditedViolationBridge(
        ViolationEventBridge(detector),
        audit,
    )

    event = bridge.process()

    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    dispatcher.dispatch(event)

    recovery = RecoveryManager(
        detector,
        lambda: True,
    )

    recovery.recover()

    assert source.read_text(
        encoding="utf-8"
    ) == original


def test_pipeline_blocks_and_recovers():
    detector = build_detector()

    violation = detector.check()

    assert violation.violated is True
    assert violation.decision == "BLOCK"

    recovered = []

    manager = RecoveryManager(
        detector,
        lambda: recovered.append(True) or True,
    )

    result = manager.recover()

    assert result.recovered is True
    assert recovered == [True]


def test_alert_dedup_is_stable():
    detector = build_detector()

    audit = InMemoryAuditSink()

    bridge = AuditedViolationBridge(
        ViolationEventBridge(detector),
        audit,
    )

    event = bridge.process()

    dispatcher = AlertDispatcher(
        AlertDedupStore()
    )

    first = dispatcher.dispatch(event)
    second = dispatcher.dispatch(event)

    assert first is not None
    assert second is None
    assert len(dispatcher.alerts) == 1
