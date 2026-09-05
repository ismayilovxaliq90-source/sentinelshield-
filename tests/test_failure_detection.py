import pytest

from sentinelshield.failure_detection import (
    FailureDetection,
    FailureEvent,
    FailureType,
)


def test_initial_state_is_clear():
    detector = FailureDetection()

    assert detector.failed is False
    assert detector.last_failure.failure_type == FailureType.NONE
    assert detector.last_failure.message == ""


def test_initial_event_is_failure_event():
    detector = FailureDetection()

    assert isinstance(detector.last_failure, FailureEvent)


def test_successful_exit_clears_failure():
    detector = FailureDetection()

    detector.detect_exit(0)

    assert detector.failed is False
    assert detector.last_failure.failure_type == FailureType.NONE


def test_nonzero_exit_is_detected():
    detector = FailureDetection()

    event = detector.detect_exit(1)

    assert event.failed is True
    assert event.failure_type == FailureType.NONZERO_EXIT
    assert event.exit_code == 1


def test_nonzero_exit_message_is_deterministic():
    detector = FailureDetection()

    event = detector.detect_exit(7)

    assert event.message == "process exited with code 7"


def test_timeout_is_detected():
    detector = FailureDetection()

    event = detector.detect_timeout()

    assert event.failed is True
    assert event.failure_type == FailureType.TIMEOUT


def test_timeout_custom_message():
    detector = FailureDetection()

    event = detector.detect_timeout("command exceeded timeout")

    assert event.message == "command exceeded timeout"


def test_resource_failure_is_detected():
    detector = FailureDetection()

    event = detector.detect_resource("RAM limit exceeded")

    assert event.failed is True
    assert event.failure_type == FailureType.RESOURCE
    assert event.message == "RAM limit exceeded"


def test_exception_failure_is_detected():
    detector = FailureDetection()

    event = detector.detect_exception("runtime exception")

    assert event.failed is True
    assert event.failure_type == FailureType.EXCEPTION


def test_validation_failure_is_detected():
    detector = FailureDetection()

    event = detector.detect_validation("invalid command")

    assert event.failed is True
    assert event.failure_type == FailureType.VALIDATION


def test_process_exit_failure_is_detected():
    detector = FailureDetection()

    event = detector.detect_process_exit()

    assert event.failed is True
    assert event.failure_type == FailureType.PROCESS_EXIT


def test_unknown_failure_is_detected():
    detector = FailureDetection()

    event = detector.detect_unknown()

    assert event.failed is True
    assert event.failure_type == FailureType.UNKNOWN


def test_clear_removes_failure():
    detector = FailureDetection()

    detector.detect_timeout()
    event = detector.clear()

    assert event.failed is False
    assert event.failure_type == FailureType.NONE
    assert event.message == ""


def test_last_failure_is_updated():
    detector = FailureDetection()

    detector.detect_resource("CPU limit exceeded")

    assert detector.last_failure.failure_type == FailureType.RESOURCE
    assert detector.last_failure.message == "CPU limit exceeded"


def test_latest_failure_replaces_previous_failure():
    detector = FailureDetection()

    detector.detect_timeout()
    detector.detect_exception("exception")

    assert detector.last_failure.failure_type == FailureType.EXCEPTION
    assert detector.last_failure.message == "exception"


def test_record_rejects_none_type():
    detector = FailureDetection()

    with pytest.raises(ValueError):
        detector.record(FailureType.NONE, "invalid")


def test_record_rejects_invalid_failure_type():
    detector = FailureDetection()

    with pytest.raises(TypeError):
        detector.record("TIMEOUT", "invalid")


def test_record_rejects_non_string_message():
    detector = FailureDetection()

    with pytest.raises(TypeError):
        detector.record(FailureType.TIMEOUT, 123)


def test_record_rejects_invalid_exit_code():
    detector = FailureDetection()

    with pytest.raises(TypeError):
        detector.record(
            FailureType.NONZERO_EXIT,
            "failed",
            exit_code="1",
        )


def test_exit_code_can_be_stored():
    detector = FailureDetection()

    event = detector.record(
        FailureType.NONZERO_EXIT,
        "command failed",
        exit_code=42,
    )

    assert event.exit_code == 42


def test_all_failure_types_can_be_recorded():
    detector = FailureDetection()

    failure_types = [
        FailureType.PROCESS_EXIT,
        FailureType.NONZERO_EXIT,
        FailureType.TIMEOUT,
        FailureType.RESOURCE,
        FailureType.EXCEPTION,
        FailureType.VALIDATION,
        FailureType.UNKNOWN,
    ]

    for failure_type in failure_types:
        event = detector.record(
            failure_type,
            f"{failure_type.value} failure",
        )

        assert event.failed is True
        assert event.failure_type == failure_type


def test_clear_after_failure_restores_clean_state():
    detector = FailureDetection()

    detector.detect_exception("failure")
    detector.clear()

    assert detector.failed is False
    assert detector.last_failure.failure_type == FailureType.NONE
    assert detector.last_failure.exit_code is None
