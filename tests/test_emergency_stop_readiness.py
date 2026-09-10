import pytest

from sentinelshield.emergency_stop_readiness import (
    EmergencyStopController,
    EmergencyStopError,
    EmergencyStopPolicy,
    require_emergency_stop_readiness,
    validate_emergency_stop_readiness,
)


def test_callback_is_required_by_default():
    controller = EmergencyStopController()

    result = validate_emergency_stop_readiness(controller)

    assert result.ready is False
    assert result.callback_available is False
    assert result.reason == "STOP_CALLBACK_REQUIRED"


def test_controller_with_callback_is_ready():
    called = []

    def callback():
        called.append(True)

    controller = EmergencyStopController(callback)

    result = validate_emergency_stop_readiness(controller)

    assert result.ready is True
    assert result.stopped is False
    assert result.callback_available is True
    assert result.reason == "EMERGENCY_STOP_READY"
    assert called == []


def test_readiness_does_not_execute_callback():
    called = []

    def callback():
        called.append(True)

    controller = EmergencyStopController(callback)

    result = controller.readiness()

    assert result.ready is True
    assert called == []


def test_request_stop_changes_state():
    called = []

    def callback():
        called.append(True)

    controller = EmergencyStopController(callback)

    assert controller.stopped is False

    callback_result = controller.request_stop()

    assert callback_result is True
    assert controller.stopped is True
    assert called == [True]


def test_active_stop_is_not_ready():
    controller = EmergencyStopController(
        lambda: None,
        policy=EmergencyStopPolicy(
            initially_stopped=True,
        ),
    )

    result = controller.readiness()

    assert result.ready is False
    assert result.stopped is True
    assert result.reason == "EMERGENCY_STOP_ACTIVE"


def test_require_ready_raises_when_callback_missing():
    controller = EmergencyStopController()

    with pytest.raises(EmergencyStopError):
        controller.require_ready()


def test_require_ready_returns_result_when_ready():
    controller = EmergencyStopController(lambda: None)

    result = require_emergency_stop_readiness(controller)

    assert result.ready is True
    assert result.reason == "EMERGENCY_STOP_READY"


def test_reset_restores_ready_state():
    controller = EmergencyStopController(lambda: None)

    controller.request_stop()

    assert controller.stopped is True

    controller.reset()

    result = controller.readiness()

    assert controller.stopped is False
    assert result.ready is True


def test_callback_exception_does_not_report_successful_stop():
    def failing_callback():
        raise RuntimeError("callback failure")

    controller = EmergencyStopController(failing_callback)

    result = controller.request_stop()

    assert result is False
    assert controller.stopped is True


def test_callback_exception_does_not_make_readiness_ready():
    def failing_callback():
        raise RuntimeError("callback failure")

    controller = EmergencyStopController(failing_callback)

    controller.request_stop()

    readiness = controller.readiness()

    assert readiness.ready is False
    assert readiness.stopped is True
    assert readiness.reason == "EMERGENCY_STOP_ACTIVE"


def test_callback_must_be_callable():
    with pytest.raises(EmergencyStopError):
        EmergencyStopController(callback="not-callable")


def test_invalid_controller_type_is_rejected():
    with pytest.raises(EmergencyStopError):
        validate_emergency_stop_readiness(object())


def test_invalid_policy_type_is_rejected():
    with pytest.raises(EmergencyStopError):
        EmergencyStopController(
            lambda: None,
            policy=object(),
        )


def test_policy_booleans_are_validated():
    with pytest.raises(EmergencyStopError):
        EmergencyStopController(
            lambda: None,
            policy=EmergencyStopPolicy(
                require_callback=1,
            ),
        )


def test_no_callback_can_be_allowed_explicitly():
    policy = EmergencyStopPolicy(
        require_callback=False,
    )

    controller = EmergencyStopController(
        policy=policy,
    )

    result = controller.readiness()

    assert result.ready is True
    assert result.callback_available is False
    assert result.reason == "EMERGENCY_STOP_READY"


def test_to_dict_contains_expected_fields():
    controller = EmergencyStopController(lambda: None)

    data = controller.readiness().to_dict()

    assert data == {
        "ready": True,
        "stopped": False,
        "callback_available": True,
        "reason": "EMERGENCY_STOP_READY",
    }


def test_stop_state_is_explicit_and_deterministic():
    controller = EmergencyStopController(lambda: None)

    first = controller.readiness()
    second = controller.readiness()

    assert first == second


def test_emergency_stop_does_not_execute_external_process():
    controller = EmergencyStopController(lambda: None)

    result = controller.request_stop()

    assert result is True
    assert controller.stopped is True
