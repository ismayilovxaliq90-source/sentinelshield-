import threading

import pytest

from sentinelshield.emergency_stop_readiness import (
    EmergencyStopController,
    EmergencyStopError,
    EmergencyStopState,
    create_emergency_stop_controller,
    require_execution_allowed,
    validate_emergency_stop_readiness,
)


def test_new_controller_is_ready():
    controller = create_emergency_stop_controller()

    result = controller.status()

    assert result.ready is True
    assert result.stop_requested is False
    assert result.stopped is False
    assert result.state == EmergencyStopState.READY


def test_readiness_validation_accepts_ready_controller():
    controller = create_emergency_stop_controller()

    result = validate_emergency_stop_readiness(controller)

    assert result.ready is True
    assert result.state == EmergencyStopState.READY


def test_execution_is_allowed_when_ready():
    controller = create_emergency_stop_controller()

    require_execution_allowed(controller)


def test_request_stop_changes_state():
    controller = create_emergency_stop_controller()

    result = controller.request_stop("manual emergency stop")

    assert result.ready is False
    assert result.stop_requested is True
    assert result.stopped is False
    assert result.state == EmergencyStopState.STOP_REQUESTED
    assert result.reason == "manual emergency stop"


def test_request_stop_blocks_execution():
    controller = create_emergency_stop_controller()

    controller.request_stop("safety trigger")

    with pytest.raises(EmergencyStopError):
        require_execution_allowed(controller)


def test_should_stop_is_true_after_request():
    controller = create_emergency_stop_controller()

    assert controller.should_stop() is False

    controller.request_stop()

    assert controller.should_stop() is True


def test_confirm_stopped_requires_prior_request():
    controller = create_emergency_stop_controller()

    with pytest.raises(EmergencyStopError):
        controller.confirm_stopped()


def test_confirm_stopped_changes_state():
    controller = create_emergency_stop_controller()

    controller.request_stop("resource violation")
    result = controller.confirm_stopped()

    assert result.state == EmergencyStopState.STOPPED
    assert result.stop_requested is True
    assert result.stopped is True


def test_stopped_state_blocks_execution():
    controller = create_emergency_stop_controller()

    controller.request_stop()
    controller.confirm_stopped()

    with pytest.raises(EmergencyStopError):
        require_execution_allowed(controller)


def test_stop_request_is_idempotent():
    controller = create_emergency_stop_controller()

    first = controller.request_stop("first reason")
    second = controller.request_stop("second reason")

    assert first.state == EmergencyStopState.STOP_REQUESTED
    assert second.state == EmergencyStopState.STOP_REQUESTED
    assert second.reason == "first reason"
    assert second.requested_at == first.requested_at


@pytest.mark.parametrize(
    "reason",
    ["", "   "],
)
def test_empty_reason_is_rejected(reason):
    controller = create_emergency_stop_controller()

    with pytest.raises(EmergencyStopError):
        controller.request_stop(reason)


@pytest.mark.parametrize(
    "reason",
    [None, 123, b"stop"],
)
def test_invalid_reason_type_is_rejected(reason):
    controller = create_emergency_stop_controller()

    with pytest.raises(EmergencyStopError):
        controller.request_stop(reason)


def test_invalid_controller_is_rejected():
    with pytest.raises(EmergencyStopError):
        validate_emergency_stop_readiness(object())


def test_require_execution_allowed_rejects_invalid_controller():
    with pytest.raises(EmergencyStopError):
        require_execution_allowed(object())


def test_status_to_dict_is_stable():
    controller = create_emergency_stop_controller()

    data = controller.status().to_dict()

    assert data == {
        "ready": True,
        "stop_requested": False,
        "stopped": False,
        "state": "READY",
        "reason": "",
    }


def test_concurrent_stop_requests_are_safe():
    controller = create_emergency_stop_controller()

    errors = []

    def request():
        try:
            controller.request_stop("concurrent stop")
        except Exception as error:
            errors.append(error)

    threads = [
        threading.Thread(target=request)
        for _ in range(32)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert controller.should_stop() is True
    assert controller.state == EmergencyStopState.STOP_REQUESTED


def test_stop_state_never_implicitly_resets():
    controller = create_emergency_stop_controller()

    controller.request_stop("emergency")
    controller.status()
    controller.status()

    assert controller.state == EmergencyStopState.STOP_REQUESTED
    assert controller.should_stop() is True


def test_validation_after_stop_request():
    controller = create_emergency_stop_controller()

    controller.request_stop("validation")

    result = validate_emergency_stop_readiness(controller)

    assert result.state == EmergencyStopState.STOP_REQUESTED
    assert result.stop_requested is True
    assert result.stopped is False


def test_validation_after_confirmed_stop():
    controller = create_emergency_stop_controller()

    controller.request_stop("confirmed")
    controller.confirm_stopped()

    result = validate_emergency_stop_readiness(controller)

    assert result.state == EmergencyStopState.STOPPED
    assert result.stop_requested is True
    assert result.stopped is True
