import pytest

from sentinelshield.failure_classification import (
    ClassificationResult,
    FailureClass,
    FailureClassifier,
)


def test_classifier_exists():
    classifier = FailureClassifier()
    assert classifier is not None


def test_clean_execution_returns_none():
    result = FailureClassifier().classify()

    assert result.failure_class == FailureClass.NONE


def test_zero_exit_returns_none():
    result = FailureClassifier().classify(exit_code=0)

    assert result.failure_class == FailureClass.NONE


def test_nonzero_exit_is_process_failure():
    result = FailureClassifier().classify(exit_code=1)

    assert result.failure_class == FailureClass.PROCESS


def test_nonzero_exit_reason():
    result = FailureClassifier().classify(exit_code=7)

    assert result.reason == "process exited with code 7"


def test_timeout_is_highest_priority():
    result = FailureClassifier().classify(
        timed_out=True,
        resource_exceeded=True,
    )

    assert result.failure_class == FailureClass.TIMEOUT


def test_resource_failure():
    result = FailureClassifier().classify(
        resource_exceeded=True,
    )

    assert result.failure_class == FailureClass.RESOURCE


def test_validation_failure():
    result = FailureClassifier().classify(
        validation_failed=True,
    )

    assert result.failure_class == FailureClass.VALIDATION


def test_exception_failure():
    result = FailureClassifier().classify(
        exception=True,
    )

    assert result.failure_class == FailureClass.EXCEPTION


def test_process_failure():
    result = FailureClassifier().classify(
        process_failed=True,
    )

    assert result.failure_class == FailureClass.PROCESS


def test_custom_reason_is_preserved():
    result = FailureClassifier().classify(
        timed_out=True,
        reason="watchdog timeout",
    )

    assert result.reason == "watchdog timeout"


def test_result_is_dataclass():
    result = FailureClassifier().classify()

    assert isinstance(result, ClassificationResult)


def test_invalid_timeout_type():
    with pytest.raises(TypeError):
        FailureClassifier().classify(timed_out="yes")


def test_invalid_resource_type():
    with pytest.raises(TypeError):
        FailureClassifier().classify(resource_exceeded="yes")


def test_invalid_validation_type():
    with pytest.raises(TypeError):
        FailureClassifier().classify(validation_failed="yes")


def test_invalid_exception_type():
    with pytest.raises(TypeError):
        FailureClassifier().classify(exception="yes")


def test_invalid_process_type():
    with pytest.raises(TypeError):
        FailureClassifier().classify(process_failed="yes")


def test_invalid_exit_code_type():
    with pytest.raises(TypeError):
        FailureClassifier().classify(exit_code="1")


def test_invalid_reason_type():
    with pytest.raises(TypeError):
        FailureClassifier().classify(reason=123)


def test_none_failure_type_maps_to_none():
    result = FailureClassifier().classify_from_failure_type("NONE")

    assert result.failure_class == FailureClass.NONE


def test_process_exit_maps_to_process():
    result = FailureClassifier().classify_from_failure_type(
        "PROCESS_EXIT"
    )

    assert result.failure_class == FailureClass.PROCESS


def test_nonzero_exit_maps_to_process():
    result = FailureClassifier().classify_from_failure_type(
        "NONZERO_EXIT"
    )

    assert result.failure_class == FailureClass.PROCESS


def test_timeout_maps_to_timeout():
    result = FailureClassifier().classify_from_failure_type("TIMEOUT")

    assert result.failure_class == FailureClass.TIMEOUT


def test_resource_maps_to_resource():
    result = FailureClassifier().classify_from_failure_type("RESOURCE")

    assert result.failure_class == FailureClass.RESOURCE


def test_unknown_maps_to_unknown():
    result = FailureClassifier().classify_from_failure_type(
        "SOMETHING_ELSE"
    )

    assert result.failure_class == FailureClass.UNKNOWN
