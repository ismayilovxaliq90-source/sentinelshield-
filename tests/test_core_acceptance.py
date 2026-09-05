from sentinelshield.core_acceptance import (
    CoreAcceptanceError,
    CoreAcceptanceReport,
    CoreCheck,
    MinimumCoreAcceptance,
)


def test_acceptance_checker_can_be_created():
    checker = MinimumCoreAcceptance()

    assert checker is not None


def test_component_manifest_is_not_empty():
    checker = MinimumCoreAcceptance()

    assert checker.COMPONENTS


def test_component_manifest_contains_core_tasks():
    checker = MinimumCoreAcceptance()

    task_numbers = {
        task
        for task, _, _, _ in checker.COMPONENTS
    }

    assert 5 in task_numbers
    assert 6 in task_numbers
    assert 7 in task_numbers
    assert 10 in task_numbers
    assert 23 in task_numbers
    assert 28 in task_numbers
    assert 35 in task_numbers
    assert 39 in task_numbers


def test_check_returns_acceptance_report():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    assert isinstance(report, CoreAcceptanceReport)


def test_report_contains_component_checks():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    assert len(report.checks) == len(
        checker.COMPONENTS
    )


def test_each_check_has_expected_type():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    assert all(
        isinstance(check, CoreCheck)
        for check in report.checks
    )


def test_existing_core_components_are_healthy():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    assert report.accepted is True
    assert all(
        check.passed
        for check in report.checks
    )


def test_workspace_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 5
    )

    assert check.passed is True


def test_project_path_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 6
    )

    assert check.passed is True


def test_command_validator_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 7
    )

    assert check.passed is True


def test_argument_validator_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 8
    )

    assert check.passed is True


def test_secret_guard_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 10
    )

    assert check.passed is True


def test_watchdog_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 23
    )

    assert check.passed is True


def test_emergency_stop_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 28
    )

    assert check.passed is True


def test_deterministic_validation_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 35
    )

    assert check.passed is True


def test_safe_state_component_is_present():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    check = next(
        item
        for item in report.checks
        if item.task == 39
    )

    assert check.passed is True


def test_require_accepted_succeeds():
    checker = MinimumCoreAcceptance()

    report = checker.require_accepted()

    assert report.accepted is True


def test_failed_acceptance_raises():
    checker = MinimumCoreAcceptance()

    original = checker.COMPONENTS

    checker.COMPONENTS = (
        (999, "Missing", "missing_module", "MissingClass"),
    )

    try:
        try:
            checker.require_accepted()
        except CoreAcceptanceError:
            passed = True
        else:
            passed = False
    finally:
        checker.COMPONENTS = original

    assert passed is True


def test_import_failure_is_reported():
    checker = MinimumCoreAcceptance()

    checker.COMPONENTS = (
        (999, "Missing", "missing_module", "MissingClass"),
    )

    report = checker.check()

    assert report.accepted is False
    assert report.checks[0].passed is False
    assert "import failed" in report.checks[0].message


def test_missing_class_is_reported():
    checker = MinimumCoreAcceptance()

    checker.COMPONENTS = (
        (5, "Workspace", "workspace", "DefinitelyMissingClass"),
    )

    report = checker.check()

    assert report.accepted is False
    assert report.checks[0].passed is False
    assert "missing component" in report.checks[0].message


def test_acceptance_does_not_execute_commands():
    checker = MinimumCoreAcceptance()

    report = checker.check()

    assert isinstance(report, CoreAcceptanceReport)
