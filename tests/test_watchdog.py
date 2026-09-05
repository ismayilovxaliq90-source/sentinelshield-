from unittest.mock import patch

import pytest

from sentinelshield.watchdog import (
    SentinelShieldWatchdog,
    WatchdogResult,
)


def test_single_check():
    watchdog = SentinelShieldWatchdog(
        "sentinelshield.service"
    )

    with patch.object(
        watchdog.health,
        "check",
        return_value=type(
            "R",
            (),
            {
                "service": "sentinelshield.service",
                "healthy": True,
            },
        )(),
    ):
        result = watchdog.check_once()

    assert isinstance(result, WatchdogResult)
    assert result.service == "sentinelshield.service"
    assert result.healthy is True
    assert result.checks == 1


def test_check_counter_increments():
    watchdog = SentinelShieldWatchdog()

    fake = type(
        "R",
        (),
        {
            "service": "sentinelshield.service",
            "healthy": True,
        },
    )()

    with patch.object(
        watchdog.health,
        "check",
        return_value=fake,
    ):
        first = watchdog.check_once()
        second = watchdog.check_once()

    assert first.checks == 1
    assert second.checks == 2


def test_unhealthy_service():
    watchdog = SentinelShieldWatchdog()

    fake = type(
        "R",
        (),
        {
            "service": "sentinelshield.service",
            "healthy": False,
        },
    )()

    with patch.object(
        watchdog.health,
        "check",
        return_value=fake,
    ):
        result = watchdog.check_once()

    assert result.healthy is False


def test_iterations():
    watchdog = SentinelShieldWatchdog()

    fake = type(
        "R",
        (),
        {
            "service": "sentinelshield.service",
            "healthy": True,
        },
    )()

    with patch.object(
        watchdog.health,
        "check",
        return_value=fake,
    ):
        results = list(
            watchdog.run(
                interval_seconds=1,
                iterations=3,
            )
        )

    assert len(results) == 3
    assert results[-1].checks == 3


def test_zero_interval_rejected():
    watchdog = SentinelShieldWatchdog()

    with pytest.raises(ValueError):
        list(
            watchdog.run(
                interval_seconds=0,
                iterations=1,
            )
        )


def test_negative_interval_rejected():
    watchdog = SentinelShieldWatchdog()

    with pytest.raises(ValueError):
        list(
            watchdog.run(
                interval_seconds=-1,
                iterations=1,
            )
        )


def test_result_is_immutable():
    result = WatchdogResult(
        service="sentinelshield.service",
        healthy=True,
        checks=1,
    )

    with pytest.raises(AttributeError):
        result.healthy = False
