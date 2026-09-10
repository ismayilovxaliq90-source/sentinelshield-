import threading

import pytest

from sentinelshield.emergency_stop_readiness import (
    EmergencyStopController,
    EmergencyStopError,
    EmergencyStopState,
    create_emergency_stop_controller,
    get_emergency_stop_status,
    reset_emergency_stop,
    require_execution_allowed,
    trigger_emergency_stop,
)


def test_controller_starts_ready():
    controller = EmergencyStopController()

    status = controller.status()

    assert status.state is EmergencyStopState.READY
    assert status.stopped is False
    assert status.reason is None
    assert status.generation == 0


def test_factory_creates_ready_controller():
    controller = create_emergency_stop_controller()

    assert isinstance(controller, EmergencyStopController)
    assert controller.is_stopped() is False


def test_trigger_activates_emergency_stop():
    controller = EmergencyStopController()

    status = controller.trigger("resource limit exceeded")

    assert status.state is EmergencyStopState.STOPPED
    assert status.stopped is True
    assert status.reason == "resource limit exceeded"
    assert status.generation == 1


def test_trigger_blocks_execution():
    controller = EmergencyStopController()

    controller.trigger("manual stop")

    with pytest.raises(EmergencyStopError):
        controller.require_execution_allowed()


def test_function_wrapper_blocks_execution():
    controller = EmergencyStopController()

    trigger_emergency_stop(controller, "security violation")

    with pytest.raises(EmergencyStopError):
        require_execution_allowed(controller)


def test_reset_restores_ready_state():
    controller = EmergencyStopController()

    controller.trigger("temporary failure")
    status = controller.reset()

    assert status.state is EmergencyStopState.READY
    assert status.stopped is False
    assert status.reason is None
    assert status.generation == 2


def test_reset_allows_execution_again():
    controller = EmergencyStopController()

    controller.trigger("temporary failure")
    controller.reset()

    require_execution_allowed(controller)


def test_repeated_trigger_does_not_replace_original_reason():
    controller = EmergencyStopController()

    first = controller.trigger("first reason")
    second = controller.trigger("second reason")

    assert first.reason == "first reason"
    assert second.reason == "first reason"
    assert second.generation == 1


@pytest.mark.parametrize(
    "reason",
    ["", "   ", None, 123, b"reason"],
)
def test_invalid_reason_is_rejected(reason):
    controller = EmergencyStopController()

    with pytest.raises(EmergencyStopError):
        controller.trigger(reason)


def test_null_character_in_reason_is_rejected():
    controller = EmergencyStopController()

    with pytest.raises(EmergencyStopError):
        controller.trigger("unsafe\x00reason")


def test_reason_is_trimmed():
    controller = EmergencyStopController()

    status = controller.trigger("   emergency condition   ")

    assert status.reason == "emergency condition"


def test_status_wrapper():
    controller = EmergencyStopController()

    status = get_emergency_stop_status(controller)

    assert status.to_dict() == {
        "state": "READY",
        "stopped": False,
        "reason": None,
        "generation": 0,
    }


def test_trigger_wrapper():
    controller = EmergencyStopController()

    status = trigger_emergency_stop(
        controller,
        "operator requested stop",
    )

    assert status.stopped is True
    assert status.reason == "operator requested stop"


def test_reset_wrapper():
    controller = EmergencyStopController()

    trigger_emergency_stop(controller, "stop")
    status = reset_emergency_stop(controller)

    assert status.stopped is False


def test_invalid_controller_is_rejected():
    with pytest.raises(EmergencyStopError):
        get_emergency_stop_status(object())

    with pytest.raises(EmergencyStopError):
        trigger_emergency_stop(object(), "reason")

    with pytest.raises(EmergencyStopError):
        reset_emergency_stop(object())

    with pytest.raises(EmergencyStopError):
        require_execution_allowed(object())


def test_to_dict_contains_expected_fields():
    controller = EmergencyStopController()

    controller.trigger("test stop")

    data = controller.status().to_dict()

    assert data["state"] == "STOPPED"
    assert data["stopped"] is True
    assert data["reason"] == "test stop"
    assert data["generation"] == 1


def test_concurrent_triggers_remain_consistent():
    controller = EmergencyStopController()

    errors = []

    def trigger() -> None:
        try:
            controller.trigger("concurrent stop")
        except Exception as error:
            errors.append(error)

    threads = [
        threading.Thread(target=trigger)
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []

    status = controller.status()

    assert status.stopped is True
    assert status.reason == "concurrent stop"
    assert status.generation == 1


def test_reset_after_concurrent_trigger_is_consistent():
    controller = EmergencyStopController()

    threads = [
        threading.Thread(
            target=controller.trigger,
            args=("stop",),
        )
        for _ in range(10)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    status = controller.reset()

    assert status.state is EmergencyStopState.READY
    assert status.stopped is False
    assert status.reason is None
