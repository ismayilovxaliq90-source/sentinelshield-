from types import SimpleNamespace

from sentinelshield.recovery import (
    RecoveryManager,
    RecoveryResult,
)


class FakeDetector:
    def __init__(self, violated):
        self.violated = violated
        self.calls = 0

    def check(self):
        self.calls += 1

        return SimpleNamespace(
            violated=self.violated,
        )


def test_no_violation_does_not_recover():
    detector = FakeDetector(False)
    calls = []

    manager = RecoveryManager(
        detector,
        lambda: calls.append(1) or True,
    )

    result = manager.recover()

    assert isinstance(result, RecoveryResult)
    assert result.attempted is False
    assert result.recovered is False
    assert result.action == "NONE"
    assert result.reason == "NO_VIOLATION"
    assert calls == []


def test_successful_recovery():
    detector = FakeDetector(True)
    calls = []

    manager = RecoveryManager(
        detector,
        lambda: calls.append(1) or True,
    )

    result = manager.recover()

    assert result.attempted is True
    assert result.recovered is True
    assert result.action == "RECOVERY_ACTION"
    assert result.reason == "RECOVERED"
    assert calls == [1]


def test_failed_recovery():
    detector = FakeDetector(True)

    manager = RecoveryManager(
        detector,
        lambda: False,
    )

    result = manager.recover()

    assert result.attempted is True
    assert result.recovered is False
    assert result.action == "RECOVERY_ACTION"
    assert result.reason == "RECOVERY_FAILED"


def test_recovery_exception_is_handled():
    detector = FakeDetector(True)

    def fail():
        raise RuntimeError("test failure")

    manager = RecoveryManager(
        detector,
        fail,
    )

    result = manager.recover()

    assert result.attempted is True
    assert result.recovered is False
    assert result.reason.startswith(
        "RECOVERY_FAILED:"
    )


def test_detector_called_once():
    detector = FakeDetector(False)

    manager = RecoveryManager(
        detector,
        lambda: True,
    )

    manager.recover()

    assert detector.calls == 1


def test_recovery_result_is_immutable():
    result = RecoveryResult(
        attempted=True,
        recovered=True,
        action="RECOVERY_ACTION",
        reason="RECOVERED",
    )

    try:
        result.recovered = False
        assert False
    except AttributeError:
        pass


def test_recovery_action_called_only_on_violation():
    calls = []

    detector = FakeDetector(False)

    manager = RecoveryManager(
        detector,
        lambda: calls.append("called") or True,
    )

    manager.recover()

    assert calls == []


def test_recovery_action_can_be_called_again_after_new_violation():
    calls = []

    detector = FakeDetector(True)

    manager = RecoveryManager(
        detector,
        lambda: calls.append("recover") or True,
    )

    first = manager.recover()
    second = manager.recover()

    assert first.recovered is True
    assert second.recovered is True
    assert calls == [
        "recover",
        "recover",
    ]
