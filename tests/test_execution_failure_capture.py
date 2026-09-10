import json

import pytest

from sentinelshield.execution_failure_capture import (
    ExecutionFailure,
    ExecutionFailureCaptureError,
    ExecutionFailureResult,
    capture_exception,
    capture_execution_failure,
    capture_execution_result,
    sanitize_command,
    sanitize_text,
    validate_execution_failure,
)


def test_success_result():
    result = capture_execution_result(
        ["echo", "ok"],
        return_code=0,
        stdout="ok\n",
    )

    assert result.failed is False
    assert result.failure.category == "NONE"
    assert result.failure.return_code == 0
    assert validate_execution_failure(result)


def test_nonzero_exit_capture():
    result = capture_execution_result(
        ["tool", "--check"],
        return_code=17,
        stderr="command failed",
    )

    assert result.failed is True
    assert result.failure.category == "NON_ZERO_EXIT"
    assert result.failure.return_code == 17
    assert validate_execution_failure(result)


@pytest.mark.parametrize(
    ("exception", "expected_category"),
    [
        (FileNotFoundError("missing"), "COMMAND_NOT_FOUND"),
        (PermissionError("denied"), "PERMISSION_ERROR"),
        (OSError("execution error"), "EXECUTION_ERROR"),
        (TimeoutError("timeout"), "TIMEOUT"),
        (RuntimeError("unexpected"), "UNEXPECTED_EXCEPTION"),
    ],
)
def test_exception_classification(
    exception,
    expected_category,
):
    result = capture_exception(
        ["tool"],
        exception,
    )

    assert result.failure.category == expected_category
    assert result.failure.exception_type == type(
        exception
    ).__name__

    if expected_category == "TIMEOUT":
        assert result.failure.timed_out is False

    assert validate_execution_failure(result)


def test_explicit_timeout_capture():
    result = capture_execution_failure(
        ["tool"],
        return_code=-15,
        timed_out=True,
        terminated=True,
    )

    assert result.failure.category == "TIMEOUT"
    assert result.failure.timed_out is True
    assert result.failure.terminated is True
    assert validate_execution_failure(result)


def test_explicit_resource_limit_capture():
    result = capture_execution_failure(
        ["tool"],
        return_code=-9,
        resource_limit_exceeded=True,
        terminated=True,
    )

    assert result.failure.category == "RESOURCE_LIMIT"
    assert result.failure.resource_limit_exceeded is True
    assert result.failure.terminated is True
    assert validate_execution_failure(result)


def test_explicit_termination_capture():
    result = capture_execution_failure(
        ["tool"],
        return_code=-15,
        terminated=True,
    )

    assert result.failure.category == "TERMINATED"
    assert result.failure.terminated is True
    assert validate_execution_failure(result)


def test_failure_priority_timeout_over_other_flags():
    result = capture_execution_failure(
        ["tool"],
        return_code=-15,
        timed_out=True,
        resource_limit_exceeded=True,
        terminated=True,
    )

    assert result.failure.category == "TIMEOUT"
    assert validate_execution_failure(result)


def test_secret_redaction():
    text = (
        "password=super-secret "
        "token=my-secret-token "
        "api_key=abc123 "
        "Bearer very-secret-token "
        "sk-123456789abcdef"
    )

    sanitized = sanitize_text(text)

    assert "super-secret" not in sanitized
    assert "my-secret-token" not in sanitized
    assert "abc123" not in sanitized
    assert "very-secret-token" not in sanitized
    assert "sk-123456789abcdef" not in sanitized
    assert "[REDACTED]" in sanitized


def test_secret_redaction_preserves_key_name():
    sanitized = sanitize_text(
        "password=super-secret"
    )

    assert sanitized == "password=[REDACTED]"


def test_command_secret_redaction():
    command = sanitize_command(
        [
            "tool",
            "--token=secret-value",
        ]
    )

    assert command[0] == "tool"
    assert "secret-value" not in command[1]
    assert "[REDACTED]" in command[1]


def test_string_command_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        sanitize_command("echo hello")


def test_bytes_command_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        sanitize_command(b"echo hello")


def test_empty_command_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        sanitize_command([])


def test_non_string_argument_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        sanitize_command(["echo", 123])


def test_null_character_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        sanitize_command(
            ["echo", "bad\x00value"]
        )


def test_bool_return_code_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        capture_execution_failure(
            ["echo"],
            return_code=True,
        )


def test_bool_status_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        capture_execution_failure(
            ["echo"],
            timed_out=1,
        )


def test_output_length_limit():
    result = capture_execution_result(
        ["tool"],
        return_code=1,
        stdout="x" * 10000,
        stderr="y" * 10000,
    )

    assert len(result.stdout) <= 4097
    assert len(result.stderr) <= 4097
    assert validate_execution_failure(result)


def test_json_serialization():
    result = capture_execution_result(
        ["echo", "ok"],
        return_code=0,
        stdout="ok\n",
    )

    payload = result.to_json()
    decoded = json.loads(payload)

    assert decoded["command"] == ["echo", "ok"]
    assert decoded["failure"]["category"] == "NONE"
    assert decoded["failed"] is False


def test_result_rejects_wrong_command_type():
    failure = ExecutionFailure(
        category="NONE",
        message="",
        exception_type=None,
        return_code=0,
        timed_out=False,
        resource_limit_exceeded=False,
        terminated=False,
    )

    with pytest.raises(ExecutionFailureCaptureError):
        ExecutionFailureResult(
            command=["echo"],
            failure=failure,
            stdout="",
            stderr="",
        )


def test_nonzero_category_requires_nonzero_code():
    with pytest.raises(ExecutionFailureCaptureError):
        ExecutionFailure(
            category="NON_ZERO_EXIT",
            message="failure",
            exception_type=None,
            return_code=0,
            timed_out=False,
            resource_limit_exceeded=False,
            terminated=False,
        )


def test_timeout_category_requires_timeout_flag():
    with pytest.raises(ExecutionFailureCaptureError):
        ExecutionFailure(
            category="TIMEOUT",
            message="timeout",
            exception_type=None,
            return_code=-15,
            timed_out=False,
            resource_limit_exceeded=False,
            terminated=True,
        )


def test_resource_category_requires_resource_flag():
    with pytest.raises(ExecutionFailureCaptureError):
        ExecutionFailure(
            category="RESOURCE_LIMIT",
            message="resource",
            exception_type=None,
            return_code=-9,
            timed_out=False,
            resource_limit_exceeded=False,
            terminated=True,
        )


def test_terminated_category_requires_termination_flag():
    with pytest.raises(ExecutionFailureCaptureError):
        ExecutionFailure(
            category="TERMINATED",
            message="terminated",
            exception_type=None,
            return_code=-15,
            timed_out=False,
            resource_limit_exceeded=False,
            terminated=False,
        )


def test_invalid_result_is_rejected():
    result = capture_execution_failure(
        ["tool"],
        return_code=0,
        timed_out=True,
    )

    assert validate_execution_failure(result) is False
