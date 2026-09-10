import sys

import pytest

from sentinelshield.resource_limit_enforcement import (
    MAX_CPU_SECONDS,
    MAX_MEMORY_MB,
    MAX_PROCESS_COUNT,
    MIN_CPU_SECONDS,
    MIN_MEMORY_MB,
    ResourceLimitError,
    ResourceLimitResult,
    ResourceLimits,
    ResourceUsage,
    enforce_resource_limits,
    validate_command,
    validate_cpu_limit,
    validate_memory_limit,
    validate_process_limit,
    validate_resource_limit_result,
)


def test_valid_resource_limits():
    limits = ResourceLimits(
        max_cpu_seconds=10,
        max_memory_mb=256,
        max_processes=10,
    )

    assert limits.max_cpu_seconds == 10.0
    assert limits.max_memory_mb == 256
    assert limits.max_processes == 10


@pytest.mark.parametrize(
    "value",
    [
        MIN_CPU_SECONDS / 2,
        MAX_CPU_SECONDS + 1,
        True,
        "10",
        None,
    ],
)
def test_invalid_cpu_limit(value):
    with pytest.raises(ResourceLimitError):
        validate_cpu_limit(value)


@pytest.mark.parametrize(
    "value",
    [
        MIN_MEMORY_MB - 1,
        MAX_MEMORY_MB + 1,
        True,
        10.5,
        "256",
    ],
)
def test_invalid_memory_limit(value):
    with pytest.raises(ResourceLimitError):
        validate_memory_limit(value)


@pytest.mark.parametrize(
    "value",
    [
        0,
        MAX_PROCESS_COUNT + 1,
        True,
        2.5,
        "4",
    ],
)
def test_invalid_process_limit(value):
    with pytest.raises(ResourceLimitError):
        validate_process_limit(value)


def test_command_rejects_string():
    with pytest.raises(ResourceLimitError):
        validate_command("echo test")


def test_command_rejects_empty():
    with pytest.raises(ResourceLimitError):
        validate_command([])


def test_command_rejects_non_string_argument():
    with pytest.raises(ResourceLimitError):
        validate_command(["echo", 123])


def test_command_rejects_null_character():
    with pytest.raises(ResourceLimitError):
        validate_command(["echo", "bad\x00value"])


def test_normal_execution(tmp_path):
    result = enforce_resource_limits(
        [sys.executable, "-c", "print('ok')"],
        limits=ResourceLimits(
            max_cpu_seconds=10,
            max_memory_mb=256,
            max_processes=10,
        ),
        working_directory=tmp_path,
    )

    assert result.return_code == 0
    assert result.limit_exceeded is False
    assert result.terminated is False
    assert "ok" in result.stdout
    assert validate_resource_limit_result(result)


def test_resource_limit_result_serialization():
    result = ResourceLimitResult(
        command=("echo", "ok"),
        return_code=0,
        usage=ResourceUsage(
            cpu_seconds=0.1,
            memory_mb=10,
            process_count=1,
        ),
        limit_exceeded=False,
        exceeded_limits=(),
        duration_seconds=0.2,
        stdout="ok\n",
        stderr="",
        terminated=False,
    )

    data = result.to_dict()

    assert data["command"] == ["echo", "ok"]
    assert data["return_code"] == 0
    assert data["usage"]["process_count"] == 1
    assert data["limit_exceeded"] is False
    assert data["success"] is True


def test_invalid_result_when_limit_exceeded_without_termination():
    result = ResourceLimitResult(
        command=("echo", "x"),
        return_code=0,
        usage=ResourceUsage(
            cpu_seconds=100,
            memory_mb=10,
            process_count=1,
        ),
        limit_exceeded=True,
        exceeded_limits=("CPU",),
        duration_seconds=1,
        stdout="",
        stderr="resource limit exceeded: CPU",
        terminated=False,
    )

    assert validate_resource_limit_result(result) is False


def test_negative_usage_rejected():
    with pytest.raises(ResourceLimitError):
        ResourceUsage(
            cpu_seconds=-1,
            memory_mb=1,
            process_count=1,
        )

    with pytest.raises(ResourceLimitError):
        ResourceUsage(
            cpu_seconds=1,
            memory_mb=-1,
            process_count=1,
        )


def test_bool_process_count_rejected():
    with pytest.raises(ResourceLimitError):
        ResourceUsage(
            cpu_seconds=1,
            memory_mb=1,
            process_count=True,
        )
