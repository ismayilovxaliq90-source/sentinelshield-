import sys

import pytest

from sentinelshield.execution_failure_capture import (
    ExecutionFailureCaptureError,
    ExecutionFailureResult,
    capture_exception,
    capture_execution_failure,
    capture_execution_result,
    sanitize_command,
    sanitize_text,
    validate_execution_failure,
)


def test_success_is_not_failure():
    result = capture_execution_result(
        ["echo", "ok"],
        return_code=0,
        stdout="ok\n",
    )

    assert result.failed is False
    assert result.failure.category == "NONE"
    assert validate_execution_failure(result)


def test_nonzero_exit_is_captured():
    result = capture_execution_result(
        ["command"],
        return_code=7,
        stderr="failed",
    )

    assert result.failed is True
    assert result.failure.category == "NON_ZERO_EXIT"
    assert result.failure.return_code == 7
    assert validate_execution_failure(result)


def test_timeout_is_captured():
    result = capture_execution_failure(
        ["command"],
        return_code=-15,
        timed_out=True,
        terminated=True,
    )

    assert result.failure.category == "TIMEOUT"
    assert result.failure.timed_out is True
    assert validate_execution_failure(result)


def test_resource_limit_is_captured():
    result = capture_execution_failure(
        ["command"],
        return_code=-15,
        resource_limit_exceeded=True,
        terminated=True,
    )

    assert result.failure.category == "RESOURCE_LIMIT"
    assert result.failure.resource_limit_exceeded is True
    assert validate_execution_failure(result)


def test_terminated_is_captured():
    result = capture_execution_failure(
        ["command"],
        return_code=-15,
        terminated=True,
    )

    assert result.failure.category == "TERMINATED"
    assert validate_execution_failure(result)


def test_file_not_found_exception():
    result = capture_exception(
        ["missing-command"],
        FileNotFoundError("command not found"),
    )

    assert result.failure.category == "COMMAND_NOT_FOUND"
    assert result.failure.exception_type == "FileNotFoundError"
    assert validate_execution_failure(result)


def test_permission_exception():
    result = capture_exception(
        ["restricted"],
        PermissionError("permission denied"),
    )

    assert result.failure.category == "PERMISSION_ERROR"
    assert validate_execution_failure(result)


def test_generic_exception():
    result = capture_exception(
        ["command"],
        RuntimeError("unexpected failure"),
    )

    assert result.failure.category == "UNEXPECTED_EXCEPTION"
    assert result.failure.exception_type == "RuntimeError"
    assert validate_execution_failure(result)


def test_secret_redaction():
    text = (
        "password=super-secret "
        "token=my-token "
        "Authorization: Bearer very-secret-token "
        "key=abc123"
    )

    sanitized = sanitize_text(text)

    assert "super-secret" not in sanitized
    assert "my-token" not in sanitized
    assert "very-secret-token" not in sanitized
    assert "abc123" not in sanitized
    assert "[REDACTED]" in sanitized


def test_command_redaction():
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
        sanitize_command("echo test")


def test_empty_command_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        sanitize_command([])


def test_null_character_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        sanitize_command(["echo", "bad\x00value"])


def test_bool_return_code_rejected():
    with pytest.raises(ExecutionFailureCaptureError):
        capture_execution_failure(
            ["echo"],
            return_code=True,
        )


def test_invalid_result_validation():
    result = capture_execution_failure(
        ["command"],
        return_code=0,
        timed_out=True,
    )

    assert validate_execution_failure(result) is False


def test_json_serialization():
    result = capture_execution_result(
        ["echo", "ok"],
        return_code=0,
        stdout="ok",
    )

    data = result.to_json()

    assert '"category": "NONE"' in data
    assert '"return_code": 0' in data


def test_output_is_bounded():
    result = capture_execution_result(
        ["echo"],
        return_code=1,
        stdout="x" * 10000,
    )

    assert len(result.stdout) <= 4097
    assert validate_execution_failure(result)


def test_none_exception_is_not_failure():
    result = capture_execution_failure(
        [sys.executable, "-c", "print('ok')"],
        return_code=0,
        exception=None,
    )

    assert result.failure.category == "NONE"
    assert result.failure.exception_type is None
