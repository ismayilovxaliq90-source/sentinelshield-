from unittest.mock import Mock

import pytest

from sentinelshield.health_check import (
    HealthCheckResult,
)
from sentinelshield.overall_health import (
    OverallHealthChecker,
    OverallHealthResult,
)
from sentinelshield.service_health import (
    ServiceHealthResult,
)


def app_health(value: bool):
    checks = {
        "PROJECT_ROOT": value,
        "SRC_PACKAGE": value,
        "TESTS": value,
        "AUDIT_PARENT": value,
        "ALERT_PARENT": value,
    }

    return HealthCheckResult(
        healthy=value,
        checks=checks,
    )


def service_health(active: bool, enabled: bool):
    return ServiceHealthResult(
        service="sentinelshield.service",
        active=active,
        enabled=enabled,
        healthy=active and enabled,
    )


def test_both_healthy():
    app = Mock()
    service = Mock()

    app.run.return_value = app_health(True)
    service.check.return_value = service_health(
        True,
        True,
    )

    result = OverallHealthChecker(
        app,
        service,
    ).check()

    assert isinstance(result, OverallHealthResult)
    assert result.healthy is True
    assert result.application_healthy is True
    assert result.service_healthy is True


def test_application_unhealthy():
    app = Mock()
    service = Mock()

    app.run.return_value = app_health(False)
    service.check.return_value = service_health(
        True,
        True,
    )

    result = OverallHealthChecker(
        app,
        service,
    ).check()

    assert result.healthy is False
    assert result.application_healthy is False
    assert result.service_healthy is True


def test_service_unhealthy():
    app = Mock()
    service = Mock()

    app.run.return_value = app_health(True)
    service.check.return_value = service_health(
        False,
        True,
    )

    result = OverallHealthChecker(
        app,
        service,
    ).check()

    assert result.healthy is False
    assert result.application_healthy is True
    assert result.service_healthy is False


def test_both_unhealthy():
    app = Mock()
    service = Mock()

    app.run.return_value = app_health(False)
    service.check.return_value = service_health(
        False,
        False,
    )

    result = OverallHealthChecker(
        app,
        service,
    ).check()

    assert result.healthy is False
    assert result.application_healthy is False
    assert result.service_healthy is False


def test_application_checker_is_called_once():
    app = Mock()
    service = Mock()

    app.run.return_value = app_health(True)
    service.check.return_value = service_health(
        True,
        True,
    )

    OverallHealthChecker(
        app,
        service,
    ).check()

    app.run.assert_called_once()


def test_service_checker_is_called_once():
    app = Mock()
    service = Mock()

    app.run.return_value = app_health(True)
    service.check.return_value = service_health(
        True,
        True,
    )

    OverallHealthChecker(
        app,
        service,
    ).check()

    service.check.assert_called_once()


def test_results_are_preserved():
    app = Mock()
    service = Mock()

    application = app_health(True)
    service_result = service_health(
        True,
        True,
    )

    app.run.return_value = application
    service.check.return_value = service_result

    result = OverallHealthChecker(
        app,
        service,
    ).check()

    assert result.application is application
    assert result.service is service_result


def test_result_is_immutable():
    result = OverallHealthResult(
        healthy=True,
        application_healthy=True,
        service_healthy=True,
        application=app_health(True),
        service=service_health(
            True,
            True,
        ),
    )

    with pytest.raises(AttributeError):
        result.healthy = False


def test_overall_requires_both_components():
    app = Mock()
    service = Mock()

    app.run.return_value = app_health(True)

    # Active but not enabled => unhealthy service.
    service.check.return_value = service_health(
        True,
        False,
    )

    result = OverallHealthChecker(
        app,
        service,
    ).check()

    assert result.healthy is False
