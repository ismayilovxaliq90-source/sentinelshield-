from types import SimpleNamespace

from sentinelshield.policy_violation_detector import (
    PolicyViolation,
    PolicyViolationDetector,
)


class FakeEnforcer:
    def __init__(
        self,
        blocked,
        decision,
        failures,
        reason,
    ):
        self.result = SimpleNamespace(
            blocked=blocked,
            decision=decision,
            failures=failures,
            reason=reason,
        )
        self.calls = 0

    def check(self):
        self.calls += 1
        return self.result


def test_safe_policy_is_not_violation():
    detector = PolicyViolationDetector(
        FakeEnforcer(
            blocked=False,
            decision="ALLOW",
            failures=(),
            reason="SAFE",
        )
    )

    result = detector.check()

    assert isinstance(
        result,
        PolicyViolation,
    )

    assert result.violated is False
    assert result.decision == "ALLOW"
    assert result.failures == ()
    assert result.reason == "SAFE"


def test_blocked_policy_is_violation():
    detector = PolicyViolationDetector(
        FakeEnforcer(
            blocked=True,
            decision="BLOCK",
            failures=("CPU",),
            reason="RESOURCE_LIMIT",
        )
    )

    result = detector.check()

    assert result.violated is True
    assert result.decision == "BLOCK"
    assert result.failures == ("CPU",)
    assert result.reason == "RESOURCE_LIMIT"


def test_multiple_failures_are_preserved():
    detector = PolicyViolationDetector(
        FakeEnforcer(
            blocked=True,
            decision="BLOCK",
            failures=("CPU", "RAM", "STORAGE"),
            reason="RESOURCE_LIMIT",
        )
    )

    result = detector.check()

    assert result.violated is True
    assert result.failures == (
        "CPU",
        "RAM",
        "STORAGE",
    )


def test_detector_calls_enforcer():
    enforcer = FakeEnforcer(
        blocked=True,
        decision="BLOCK",
        failures=("CPU",),
        reason="RESOURCE_LIMIT",
    )

    detector = PolicyViolationDetector(enforcer)

    detector.check()

    assert enforcer.calls == 1


def test_detector_calls_enforcer_each_time():
    enforcer = FakeEnforcer(
        blocked=False,
        decision="ALLOW",
        failures=(),
        reason="SAFE",
    )

    detector = PolicyViolationDetector(enforcer)

    detector.check()
    detector.check()

    assert enforcer.calls == 2


def test_violation_result_is_immutable():
    result = PolicyViolation(
        violated=True,
        decision="BLOCK",
        failures=("CPU",),
        reason="RESOURCE_LIMIT",
    )

    try:
        result.violated = False
        assert False
    except AttributeError:
        pass


def test_empty_failure_list_is_tuple():
    detector = PolicyViolationDetector(
        FakeEnforcer(
            blocked=False,
            decision="ALLOW",
            failures=[],
            reason="SAFE",
        )
    )

    result = detector.check()

    assert isinstance(
        result.failures,
        tuple,
    )


def test_violation_reason_is_preserved():
    detector = PolicyViolationDetector(
        FakeEnforcer(
            blocked=True,
            decision="BLOCK",
            failures=("RAM",),
            reason="MEMORY_LIMIT",
        )
    )

    result = detector.check()

    assert result.reason == "MEMORY_LIMIT"
