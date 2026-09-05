import pytest

from sentinelshield.execution_state import (
    ExecutionStateError,
    ExecutionStateTracker,
    ExecutionStatus,
)


class FakeClock:
    def __init__(self, value=100.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def test_execution_id_must_be_string():
    with pytest.raises(TypeError):
        ExecutionStateTracker(123)


def test_execution_id_cannot_be_empty():
    with pytest.raises(ValueError):
        ExecutionStateTracker("")


def test_execution_id_whitespace_is_rejected():
    with pytest.raises(ValueError):
        ExecutionStateTracker("   ")


def test_initial_state_is_pending():
    tracker = ExecutionStateTracker("exec-1")

    state = tracker.snapshot()

    assert state.execution_id == "exec-1"
    assert state.status == ExecutionStatus.PENDING
    assert state.return_code is None
    assert state.message == ""


def test_start_moves_pending_to_running():
    tracker = ExecutionStateTracker("exec-1")

    state = tracker.start("started")

    assert state.status == ExecutionStatus.RUNNING
    assert state.message == "started"


def test_success_moves_running_to_success():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    state = tracker.succeed()

    assert state.status == ExecutionStatus.SUCCESS
    assert state.return_code == 0


def test_success_can_store_message():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    state = tracker.succeed(
        message="completed"
    )

    assert state.message == "completed"


def test_success_requires_zero_return_code():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()

    with pytest.raises(ValueError):
        tracker.succeed(return_code=1)


def test_fail_moves_running_to_failed():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    state = tracker.fail(
        return_code=7,
        message="command failed",
    )

    assert state.status == ExecutionStatus.FAILED
    assert state.return_code == 7
    assert state.message == "command failed"


def test_timeout_moves_running_to_timed_out():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    state = tracker.timeout(
        message="execution timeout"
    )

    assert state.status == ExecutionStatus.TIMED_OUT
    assert state.message == "execution timeout"


def test_stop_moves_running_to_stopped():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    state = tracker.stop(
        message="manual stop"
    )

    assert state.status == ExecutionStatus.STOPPED
    assert state.message == "manual stop"


def test_pending_can_fail():
    tracker = ExecutionStateTracker("exec-1")

    state = tracker.fail(
        message="validation failure"
    )

    assert state.status == ExecutionStatus.FAILED
    assert tracker.is_final() is True


def test_pending_can_be_stopped():
    tracker = ExecutionStateTracker("exec-1")

    state = tracker.stop()

    assert state.status == ExecutionStatus.STOPPED
    assert tracker.is_final() is True


def test_pending_cannot_succeed_directly():
    tracker = ExecutionStateTracker("exec-1")

    with pytest.raises(ExecutionStateError):
        tracker.succeed()


def test_pending_cannot_timeout_directly():
    tracker = ExecutionStateTracker("exec-1")

    with pytest.raises(ExecutionStateError):
        tracker.timeout()


def test_running_cannot_start_again():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()

    with pytest.raises(ExecutionStateError):
        tracker.start()


def test_final_state_cannot_change():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    tracker.succeed()

    with pytest.raises(ExecutionStateError):
        tracker.fail()

    with pytest.raises(ExecutionStateError):
        tracker.stop()


def test_updated_time_changes_on_transition():
    clock = FakeClock()
    tracker = ExecutionStateTracker(
        "exec-1",
        clock=clock,
    )

    first = tracker.snapshot()

    clock.advance(3)

    second = tracker.start()

    assert second.created_at == first.created_at
    assert second.updated_at == 103.0


def test_state_snapshot_is_immutable():
    tracker = ExecutionStateTracker("exec-1")

    state = tracker.snapshot()

    with pytest.raises(AttributeError):
        state.status = ExecutionStatus.RUNNING


def test_is_final_for_success():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    tracker.succeed()

    assert tracker.is_final() is True


def test_is_final_for_failed():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    tracker.fail()

    assert tracker.is_final() is True


def test_is_final_for_timeout():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    tracker.timeout()

    assert tracker.is_final() is True


def test_is_final_for_stopped():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()
    tracker.stop()

    assert tracker.is_final() is True


def test_running_is_not_final():
    tracker = ExecutionStateTracker("exec-1")

    tracker.start()

    assert tracker.is_final() is False


def test_snapshot_preserves_execution_id():
    tracker = ExecutionStateTracker("sentinel-123")

    tracker.start()

    assert tracker.snapshot().execution_id == "sentinel-123"
