from types import SimpleNamespace

from sentinelshield.violation_event_bridge import (
    AuditedViolationBridge,
    InMemoryAuditSink,
    ViolationEvent,
    ViolationEventBridge,
)


class FakeDetector:
    def __init__(
        self,
        violated=True,
        decision="BLOCK",
        failures=("CPU",),
        reason="RESOURCE_LIMIT",
    ):
        self.result = SimpleNamespace(
            violated=violated,
            decision=decision,
            failures=failures,
            reason=reason,
        )
        self.calls = 0

    def check(self):
        self.calls += 1
        return self.result


def test_violation_creates_event():
    bridge = ViolationEventBridge(
        FakeDetector()
    )

    event = bridge.create_event()

    assert isinstance(event, ViolationEvent)
    assert event.event_type == "POLICY_VIOLATION"
    assert event.decision == "BLOCK"
    assert event.failures == ("CPU",)
    assert event.reason == "RESOURCE_LIMIT"
    assert event.timestamp


def test_safe_result_creates_no_event():
    bridge = ViolationEventBridge(
        FakeDetector(
            violated=False,
            decision="ALLOW",
            failures=(),
            reason="SAFE",
        )
    )

    assert bridge.create_event() is None


def test_failures_are_tuple():
    bridge = ViolationEventBridge(
        FakeDetector(
            failures=["CPU", "RAM"],
        )
    )

    event = bridge.create_event()

    assert event is not None
    assert isinstance(event.failures, tuple)
    assert event.failures == ("CPU", "RAM")


def test_event_is_immutable():
    event = ViolationEvent(
        event_type="POLICY_VIOLATION",
        timestamp="now",
        decision="BLOCK",
        failures=("CPU",),
        reason="LIMIT",
    )

    try:
        event.decision = "ALLOW"
        assert False
    except AttributeError:
        pass


def test_detector_is_called():
    detector = FakeDetector()
    bridge = ViolationEventBridge(detector)

    bridge.create_event()

    assert detector.calls == 1


def test_audit_sink_receives_event():
    audit = InMemoryAuditSink()

    bridge = AuditedViolationBridge(
        ViolationEventBridge(
            FakeDetector()
        ),
        audit,
    )

    event = bridge.process()

    assert event is not None
    assert len(audit.events) == 1
    assert audit.events[0] == event


def test_safe_event_is_not_written():
    audit = InMemoryAuditSink()

    bridge = AuditedViolationBridge(
        ViolationEventBridge(
            FakeDetector(
                violated=False,
                decision="ALLOW",
                failures=(),
                reason="SAFE",
            )
        ),
        audit,
    )

    assert bridge.process() is None
    assert audit.events == []


def test_multiple_events_are_audited():
    detector = FakeDetector()
    audit = InMemoryAuditSink()

    bridge = AuditedViolationBridge(
        ViolationEventBridge(detector),
        audit,
    )

    first = bridge.process()
    second = bridge.process()

    assert first is not None
    assert second is not None
    assert len(audit.events) == 2


def test_event_timestamp_is_utc_iso():
    bridge = ViolationEventBridge(
        FakeDetector()
    )

    event = bridge.create_event()

    assert event is not None
    assert event.timestamp.endswith("+00:00")
