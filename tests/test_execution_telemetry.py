from datetime import datetime, timezone

import pytest

from sentinelshield.execution_telemetry import (
    ExecutionTelemetry,
    ExecutionTelemetryCollector,
    ExecutionTelemetryError,
    create_execution_telemetry,
    validate_execution_telemetry,
)


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_create_valid_telemetry():
    result = create_execution_telemetry(
        execution_id="exec-001",
        command=["npm", "install"],
        status="completed",
        started_at=timestamp(),
        completed_at=timestamp(),
        duration_seconds=1.25,
        return_code=0,
        stdout="ok",
        stderr="",
    )

    assert result.execution_id == "exec-001"
    assert result.status == "completed"
    assert result.return_code == 0
    assert result.stdout_bytes == 2
    assert validate_execution_telemetry(result) is True


def test_command_must_not_be_string():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            command="npm install",
            status="completed",
            started_at=timestamp(),
        )


def test_negative_duration_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            command=["npm", "install"],
            status="completed",
            started_at=timestamp(),
            duration_seconds=-1,
        )


def test_invalid_status_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            command=["npm"],
            status="unknown",
            started_at=timestamp(),
        )


def test_timeout_requires_timeout_status():
    telemetry = ExecutionTelemetry(
        execution_id="exec",
        status="completed",
        started_at=timestamp(),
        timed_out=True,
    )

    assert validate_execution_telemetry(telemetry) is False


def test_secret_metadata_is_redacted():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        command=["tool", "--token=super-secret-value"],
        status="completed",
        started_at=timestamp(),
        metadata={
            "api_token": "super-secret-value",
            "safe": "value",
        },
    )

    data = telemetry.to_dict()

    assert data["metadata"]["api_token"] == "[REDACTED]"
    assert "super-secret-value" not in telemetry.to_json()


def test_secret_output_is_redacted():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        command=["tool"],
        status="completed",
        started_at=timestamp(),
        stdout="token=super-secret-value",
    )

    assert "super-secret-value" not in telemetry.to_json()
    assert "[REDACTED]" in telemetry.stdout_preview


def test_output_size_is_recorded():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        command=["tool"],
        status="completed",
        started_at=timestamp(),
        stdout="hello",
        stderr="error",
    )

    assert telemetry.stdout_bytes == 5
    assert telemetry.stderr_bytes == 5


def test_output_preview_is_bounded():
    value = "x" * 10000

    telemetry = create_execution_telemetry(
        execution_id="exec",
        command=["tool"],
        status="completed",
        started_at=timestamp(),
        stdout=value,
    )

    assert len(telemetry.stdout_preview) <= 4100
    assert "[TRUNCATED]" in telemetry.stdout_preview


def test_collector_start_and_finish():
    collector = ExecutionTelemetryCollector.start(
        execution_id="exec-002",
        command=["python", "-m", "tool"],
        metadata={"phase": "remediation"},
    )

    result = collector.finish(
        status="completed",
        duration_seconds=2.0,
        return_code=0,
        stdout="done",
    )

    assert result.execution_id == "exec-002"
    assert result.status == "completed"
    assert result.duration_seconds == 2.0
    assert result.metadata["phase"] == "remediation"


def test_timeout_collection():
    collector = ExecutionTelemetryCollector.start(
        execution_id="exec-timeout",
        command=["tool"],
    )

    result = collector.finish(
        status="timeout",
        duration_seconds=10.0,
        timed_out=True,
    )

    assert result.status == "timeout"
    assert result.timed_out is True
    assert validate_execution_telemetry(result) is True


def test_resource_usage_is_serializable():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        command=["tool"],
        status="completed",
        started_at=timestamp(),
        resource_usage={
            "cpu_seconds": 1.2,
            "peak_rss_bytes": 1024,
        },
    )

    data = telemetry.to_dict()

    assert data["resource_usage"]["cpu_seconds"] == 1.2
    assert data["resource_usage"]["peak_rss_bytes"] == 1024


def test_json_serialization():
    telemetry = create_execution_telemetry(
        execution_id="exec",
        command=["tool"],
        status="completed",
        started_at=timestamp(),
    )

    text = telemetry.to_json()

    assert isinstance(text, str)
    assert '"execution_id": "exec"' in text


def test_empty_execution_id_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="   ",
            command=["tool"],
            status="completed",
            started_at=timestamp(),
        )


def test_invalid_timestamp_rejected():
    with pytest.raises(ExecutionTelemetryError):
        create_execution_telemetry(
            execution_id="exec",
            command=["tool"],
            status="completed",
            started_at="not-a-timestamp",
        )
