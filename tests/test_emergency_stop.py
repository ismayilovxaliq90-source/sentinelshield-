import pytest

from sentinelshield.emergency_stop import (
    EmergencyStop,
    EmergencyStopError,
    StopReason,
)


def test_initial_state_is_clear():
    stop = EmergencyStop()
    state = stop.state()

    assert state.active is False
    assert state.reason is None
    assert state.message == ""


def test_initial_can_execute_is_true():
    stop = EmergencyStop()
    assert stop.can_execute() is True


def test_initial_require_clear_succeeds():
    stop = EmergencyStop()
    stop.require_clear()


def test_manual_trigger_activates_stop():
    stop = EmergencyStop()

    state = stop.trigger()

    assert state.active is True
    assert state.reason == StopReason.MANUAL


def test_trigger_stores_reason():
    stop = EmergencyStop()

    state = stop.trigger(
        reason=StopReason.WATCHDOG
    )

    assert state.reason == StopReason.WATCHDOG


def test_trigger_stores_message():
    stop = EmergencyStop()

    state = stop.trigger(
        message="watchdog heartbeat lost"
    )

    assert state.message == "watchdog heartbeat lost"


def test_active_stop_blocks_execution():
    stop = EmergencyStop()

    stop.trigger()

    assert stop.can_execute() is False


def test_require_clear_raises_when_active():
    stop = EmergencyStop()

    stop.trigger()

    with pytest.raises(EmergencyStopError):
        stop.require_clear()


def test_invalid_reason_is_rejected():
    stop = EmergencyStop()

    with pytest.raises(TypeError):
        stop.trigger(reason="MANUAL")


def test_invalid_message_is_rejected():
    stop = EmergencyStop()

    with pytest.raises(TypeError):
        stop.trigger(message=123)


def test_duplicate_trigger_does_not_change_existing_state():
    stop = EmergencyStop()

    first = stop.trigger(
        reason=StopReason.MANUAL,
        message="first",
    )

    second = stop.trigger(
        reason=StopReason.WATCHDOG,
        message="second",
    )

    assert second == first


def test_clear_deactivates_stop():
    stop = EmergencyStop()

    stop.trigger()

    state = stop.clear()

    assert state.active is False
    assert state.reason is None
    assert state.message == ""


def test_clear_allows_execution_again():
    stop = EmergencyStop()

    stop.trigger()
    stop.clear()

    assert stop.can_execute() is True


def test_clear_without_active_stop_is_rejected():
    stop = EmergencyStop()

    with pytest.raises(EmergencyStopError):
        stop.clear()


def test_generation_changes_on_trigger():
    stop = EmergencyStop()

    initial = stop.state().generation
    state = stop.trigger()

    assert state.generation == initial + 1


def test_generation_changes_on_clear():
    stop = EmergencyStop()

    stop.trigger()
    before = stop.state().generation

    state = stop.clear()

    assert state.generation == before + 1


def test_reset_returns_clear_state():
    stop = EmergencyStop()

    stop.trigger(
        reason=StopReason.FAILURE,
        message="failure detected",
    )

    state = stop.reset()

    assert state.active is False
    assert state.reason is None
    assert state.message == ""


def test_reset_allows_execution():
    stop = EmergencyStop()

    stop.trigger()
    stop.reset()

    assert stop.can_execute() is True


def test_all_stop_reasons_are_supported():
    stop = EmergencyStop()

    for reason in StopReason:
        stop.reset()

        state = stop.trigger(reason=reason)

        assert state.active is True
        assert state.reason == reason
