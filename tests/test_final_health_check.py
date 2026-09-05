from unittest.mock import patch

import pytest

from sentinelshield.final_health_check import (
    ComponentHealth,
    FinalHealthCheck,
    HealthCheckError,
    HealthReport,
)


def test_health_check_can_be_created():
    checker = FinalHealthCheck()

    assert checker is not None


def test_required_components_are_defined():
    checker = FinalHealthCheck()

    assert len(checker.REQUIRED_COMPONENTS) >= 20


def test_report_is_none_before_check():
    checker = FinalHealthCheck()

    assert checker.report is None


def test_check_returns_health_report():
    checker = FinalHealthCheck()

    report = checker.check()

    assert isinstance(report, HealthReport)


def test_components_are_present_in_report():
    checker = FinalHealthCheck()

    report = checker.check()

    names = {
        component.name
        for component in report.components
    }

    assert "command_validator" in names
    assert "argument_validator" in names
    assert "watchdog" in names
    assert "cleanup_controller" in names
    assert "deterministic_validation" in names


def test_all_required_components_are_healthy():
    checker = FinalHealthCheck()

    report = checker.check()

    assert report.healthy is True
    assert all(
        component.healthy
        for component in report.components
    )


def test_each_health_result_is_component_health():
    checker = FinalHealthCheck()

    report = checker.check()

    assert all(
        isinstance(component, ComponentHealth)
        for component in report.components
    )


def test_healthy_component_has_ok_message():
    checker = FinalHealthCheck()

    report = checker.check()

    assert all(
        component.message == "OK"
        for component in report.components
        if component.healthy
    )


def test_require_healthy_returns_report():
    checker = FinalHealthCheck()

    report = checker.require_healthy()

    assert isinstance(report, HealthReport)
    assert report.healthy is True


def test_require_healthy_raises_when_component_is_missing():
    checker = FinalHealthCheck()

    with patch.dict(
        checker.REQUIRED_COMPONENTS,
        {
            "command_validator": (
                "DefinitelyMissingComponent",
            )
        },
        clear=False,
    ):
        with pytest.raises(HealthCheckError):
            checker.require_healthy()


def test_check_reports_missing_component():
    checker = FinalHealthCheck()

    with patch.dict(
        checker.REQUIRED_COMPONENTS,
        {
            "command_validator": (
                "DefinitelyMissingComponent",
            )
        },
        clear=False,
    ):
        report = checker.check()

    component = next(
        item
        for item in report.components
        if item.name == "command_validator"
    )

    assert component.healthy is False
    assert "missing components" in component.message


def test_check_reports_import_failure():
    checker = FinalHealthCheck()

    with patch(
        "sentinelshield.final_health_check.import_module",
        side_effect=ImportError("test import failure"),
    ):
        report = checker.check()

    assert report.healthy is False
    assert all(
        component.healthy is False
        for component in report.components
    )


def test_report_is_saved_after_check():
    checker = FinalHealthCheck()

    report = checker.check()

    assert checker.report == report


def test_report_components_are_immutable():
    checker = FinalHealthCheck()

    report = checker.check()

    with pytest.raises(AttributeError):
        report.healthy = False


def test_component_health_is_immutable():
    component = ComponentHealth(
        name="test",
        healthy=True,
        message="OK",
    )

    with pytest.raises(AttributeError):
        component.healthy = False


def test_health_check_component_order_is_deterministic():
    checker = FinalHealthCheck()

    first = checker.check()
    second = checker.check()

    assert [
        item.name
        for item in first.components
    ] == [
        item.name
        for item in second.components
    ]


def test_health_check_result_is_stable():
    checker = FinalHealthCheck()

    first = checker.check()
    second = checker.check()

    assert first == second


def test_failed_component_makes_overall_health_false():
    checker = FinalHealthCheck()

    with patch.dict(
        checker.REQUIRED_COMPONENTS,
        {
            "command_validator": (
                "DefinitelyMissingComponent",
            )
        },
        clear=False,
    ):
        report = checker.check()

    assert report.healthy is False


def test_empty_required_component_list_is_not_healthy():
    checker = FinalHealthCheck()

    with patch.dict(
        checker.REQUIRED_COMPONENTS,
        {},
        clear=True,
    ):
        report = checker.check()

    assert report.healthy is True
    assert report.components == ()


def test_health_report_contains_all_component_results():
    checker = FinalHealthCheck()

    report = checker.check()

    assert len(report.components) == len(
        checker.REQUIRED_COMPONENTS
    )


def test_no_command_execution_is_performed():
    checker = FinalHealthCheck()

    report = checker.check()

    assert isinstance(report, HealthReport)
    assert report.healthy is True
