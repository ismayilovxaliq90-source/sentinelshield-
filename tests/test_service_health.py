from unittest.mock import patch

import pytest

from sentinelshield.service_health import (
    ServiceHealthResult,
    SystemdServiceHealth,
)


def test_invalid_service_type():
    with pytest.raises(TypeError):
        SystemdServiceHealth(None)


def test_empty_service_rejected():
    with pytest.raises(ValueError):
        SystemdServiceHealth("")


def test_whitespace_service_rejected():
    with pytest.raises(ValueError):
        SystemdServiceHealth("   ")


@patch("sentinelshield.service_health.subprocess.run")
def test_active_and_enabled(mock_run):
    mock_run.side_effect = [
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "active\n",
            },
        )(),
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "enabled\n",
            },
        )(),
    ]

    result = SystemdServiceHealth(
        "sentinelshield.service"
    ).check()

    assert isinstance(result, ServiceHealthResult)
    assert result.active is True
    assert result.enabled is True
    assert result.healthy is True


@patch("sentinelshield.service_health.subprocess.run")
def test_inactive_service(mock_run):
    mock_run.side_effect = [
        type(
            "Result",
            (),
            {
                "returncode": 3,
                "stdout": "inactive\n",
            },
        )(),
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "enabled\n",
            },
        )(),
    ]

    result = SystemdServiceHealth(
        "sentinelshield.service"
    ).check()

    assert result.active is False
    assert result.enabled is True
    assert result.healthy is False


@patch("sentinelshield.service_health.subprocess.run")
def test_disabled_service(mock_run):
    mock_run.side_effect = [
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "active\n",
            },
        )(),
        type(
            "Result",
            (),
            {
                "returncode": 1,
                "stdout": "disabled\n",
            },
        )(),
    ]

    result = SystemdServiceHealth(
        "sentinelshield.service"
    ).check()

    assert result.active is True
    assert result.enabled is False
    assert result.healthy is False


@patch("sentinelshield.service_health.subprocess.run")
def test_both_failed(mock_run):
    mock_run.side_effect = [
        type(
            "Result",
            (),
            {
                "returncode": 3,
                "stdout": "inactive\n",
            },
        )(),
        type(
            "Result",
            (),
            {
                "returncode": 1,
                "stdout": "disabled\n",
            },
        )(),
    ]

    result = SystemdServiceHealth(
        "sentinelshield.service"
    ).check()

    assert result.active is False
    assert result.enabled is False
    assert result.healthy is False


@patch("sentinelshield.service_health.subprocess.run")
def test_systemctl_commands_are_read_only(mock_run):
    mock_run.side_effect = [
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "active\n",
            },
        )(),
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "enabled\n",
            },
        )(),
    ]

    SystemdServiceHealth(
        "sentinelshield.service"
    ).check()

    commands = [
        call.args[0]
        for call in mock_run.call_args_list
    ]

    assert commands == [
        ["systemctl", "is-active", "sentinelshield.service"],
        ["systemctl", "is-enabled", "sentinelshield.service"],
    ]


@patch("sentinelshield.service_health.subprocess.run")
def test_service_name_is_preserved(mock_run):
    mock_run.side_effect = [
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "active\n",
            },
        )(),
        type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "enabled\n",
            },
        )(),
    ]

    result = SystemdServiceHealth(
        "custom.service"
    ).check()

    assert result.service == "custom.service"


def test_result_is_immutable():
    result = ServiceHealthResult(
        service="sentinelshield.service",
        active=True,
        enabled=True,
        healthy=True,
    )

    with pytest.raises(AttributeError):
        result.healthy = False
