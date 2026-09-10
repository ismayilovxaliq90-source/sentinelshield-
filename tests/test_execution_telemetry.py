from datetime import datetime, timezone

import pytest

from sentinelshield.execution_telemetry import (
    ExecutionTelemetry,
    ExecutionTelemetryCollector,
    ExecutionTelemetryError,
    create_execution_telemetry,
    sanitize_command,
    sanitize_mapping,
    validate_execution_telemetry,
)


def ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_completed_execution():
    telemetry = create_execution_telemetry(
        execution_id="exec-001",
        status="completed",
        started_at=ts(),
        completed_at=ts(),
        duration_seconds=1.5,
        command=["npm", "install"],
        return_code=0,
        stdout="completed",
        stderr="",
    )

    assert telemetry.execution_id == "exec-001"
    assert telemetry.status == "completed"
    assert telemetry.return_code == 0
    assert telemetry.stdout_bytes > 0
    assert validate_execution_telemetry(telemetry)


def test_failed_execution():
    telemetry = create_execution_telemetry(
        execution_id="exec-failed",
        status="failed",
        started_at=ts(),
        command=["tool"],
        return_code=1,
        stderr="command failed",
    )

    assert telemetry.status == "failed"
    assert telemetry.return_code == 1
    assert validate_execution_telemetry(telemetry)


def test_timeout_execution():
    telemetry = create_execution_telemetry(
        execution_id="exec-timeout",
        status="timeout",
        started_at=ts(),
        command=["tool"],
        duration_seconds=30,
        timed_out=True,
    )

    assert telemetry.timed_out is True
    assert telemetry.status == "timeout"
    assert validate_execution_telemetry(telemetry)


def test_terminated_execution():
    telemetry = create_execution_telemetry(
        execution_id="exec-terminated",
        status="terminated",
        started_at=ts(),
        command=["tool"],
        terminated=True,
    )

    assert telemetry.terminated is True
    assert telemetry.status == "terminated"
    assert validate_execution_telemetry(telemetry)


def test_command_string_rejected():
    with pytest.raises(ExecutionTelemetryError):
        sanitize_command("npm install")


def test_non_string_command_argument_rejected():
    with pytest.raises(ExecutionTelemetryError):
        sanitize_command(["npm", 123])


def test_invalid_status_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            status="invalid",
            started_at=ts(),
            command=["tool"],
        )


def test_invalid_timestamp_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            status="started",
            started_at="invalid",
            command=["tool"],
        )


def test_timezone_is_required():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            status="started",
            started_at="2026-01-01T00:00:00",
            command=["tool"],
        )


def test_negative_duration_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            status="completed",
            started_at=ts(),
            command=["tool"],
            duration_seconds=-1,
        )


def test_negative_output_size_rejected():
    with pytest.raises(ExecutionTelemetryError):
        ExecutionTelemetry(
            execution_id="exec",
            status="completed",
            started_at=ts(),
            stdout_bytes=-1,
        )


def test_timeout_flag_requires_timeout_status():
    with pytest.raises(ExecutionTelemetryError):
        ExecutionTelemetry(
            execution_id="exec",
            status="completed",
            started_at=ts(),
            timed_out=True,
        )


def test_termination_flag_requires_terminated_status():
    with pytest.raises(ExecutionTelemetryError):
        ExecutionTelemetry(
            execution_id="exec",
            status="failed",
            started_at=ts(),
            terminated=True,
        )


def test_secret_metadata_is_redacted():
    metadata = sanitize_mapping(
        {
            "api_token": "super-secret-value",
            "safe": "value",
        }
    )

    assert metadata["api_token"] == "[REDACTED]"
    assert metadata["safe"] == "value"


def test_secret_command_argument_is_redacted():
    command = sanitize_command(
        [
            "tool",
            "--token=super-secret-value",
        ]
    )

    assert command[1] == "[REDACTED]"
    assert "super-secret-value" not in str(command)


def test_secret_output_is_redacted():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        status="completed",
        started_at=ts(),
        command=["tool"],
        stdout="token=super-secret-value",
    )

    serialized = telemetry.to_json()

    assert "super-secret-value" not in serialized
    assert "[REDACTED]" in serialized


def test_authorization_header_is_redacted():
    metadata = sanitize_mapping(
        {
            "Authorization": "Bearer abcdefghijk",
        }
    )

    assert metadata["Authorization"] == "[REDACTED]"


def test_output_preview_is_bounded():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        status="completed",
        started_at=ts(),
        command=["tool"],
        stdout="x" * 10000,
    )

    assert len(telemetry.stdout_preview) <= 4100
    assert "[TRUNCATED]" in telemetry.stdout_preview


def test_output_byte_count_uses_utf8():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        status="completed",
        started_at=ts(),
        command=["tool"],
        stdout="ə",
    )

    assert telemetry.stdout_bytes == len(
        "ə".encode("utf-8")
    )


def test_collector_lifecycle():
    collector = ExecutionTelemetryCollector.start(
        execution_id="exec-lifecycle",
        command=["tool", "--safe"],
        metadata={"task": 210},
    )

    telemetry = collector.finish(
        status="completed",
        duration_seconds=2.25,
        return_code=0,
        stdout="done",
    )

    assert telemetry.execution_id == "exec-lifecycle"
    assert telemetry.status == "completed"
    assert telemetry.duration_seconds == 2.25
    assert telemetry.metadata["task"] == 210
    assert validate_execution_telemetry(telemetry)


def test_collector_metadata_is_redacted():
    collector = ExecutionTelemetryCollector.start(
        execution_id="exec",
        command=["tool"],
        metadata={"secret": "hidden"},
    )

    telemetry = collector.finish(
        status="completed",
    )

    assert telemetry.metadata["secret"] == "[REDACTED]"
    assert "hidden" not in telemetry.to_json()


def test_resource_metadata():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        status="completed",
        started_at=ts(),
        command=["tool"],
        resource_usage={
            "cpu_seconds": 1.25,
            "peak_rss_bytes": 1048576,
        },
    )

    assert (
        telemetry.resource_usage["cpu_seconds"]
        == 1.25
    )
    assert (
        telemetry.resource_usage["peak_rss_bytes"]
        == 1048576
    )


def test_json_serialization():
    telemetry = create_execution_telemetry(
        execution_id="exec-json",
        status="completed",
        started_at=ts(),
        command=["tool"],
    )

    value = telemetry.to_json()

    assert isinstance(value, str)
    assert '"execution_id":"exec-json"' in value


def test_empty_execution_id_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id=" ",
            status="started",
            started_at=ts(),
            command=["tool"],
        )


def test_invalid_return_code_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            status="completed",
            started_at=ts(),
            command=["tool"],
            return_code=True,
        )


def test_invalid_metadata_rejected():
    with pytest.raises(ExecutionTelemetryError):
        sanitize_mapping(["invalid"])


def test_validation_rejects_wrong_object():
    assert validate_execution_telemetry(None) is False
