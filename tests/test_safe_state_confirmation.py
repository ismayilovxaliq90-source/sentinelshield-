import pytest

from sentinelshield.safe_state_confirmation import (
    SafeStateConfirmation,
    SafeStateError,
    SafeStateReport,
    SafetyCheck,
)


def make_checks():
    return [
        SafetyCheck(
            name=name,
            passed=True,
            message="OK",
        )
        for name in SafeStateConfirmation.REQUIRED_CHECKS
    ]


def test_checker_can_be_created():
    checker = SafeStateConfirmation()

    assert checker is not None


def test_report_is_none_before_confirmation():
    checker = SafeStateConfirmation()

    assert checker.report is None


def test_safety_check_is_immutable():
    check = SafetyCheck(
        name="workspace",
        passed=True,
        message="OK",
    )

    with pytest.raises(AttributeError):
        check.passed = False


def test_safe_state_report_is_immutable():
    report = SafeStateReport(
        safe=True,
        checks=(),
    )

    with pytest.raises(AttributeError):
        report.safe = False


def test_all_required_checks_pass():
    checker = SafeStateConfirmation()

    report = checker.confirm(
        make_checks()
    )

    assert isinstance(report, SafeStateReport)
    assert report.safe is True


def test_all_required_checks_are_present():
    checker = SafeStateConfirmation()

    report = checker.confirm(
        make_checks()
    )

    names = {
        check.name
        for check in report.checks
    }

    for name in SafeStateConfirmation.REQUIRED_CHECKS:
        assert name in names


def test_failed_check_makes_state_unsafe():
    checker = SafeStateConfirmation()

    checks = make_checks()

    checks[0] = SafetyCheck(
        name=checks[0].name,
        passed=False,
        message="FAILED",
    )

    report = checker.confirm(checks)

    assert report.safe is False


def test_missing_required_check_is_rejected():
    checker = SafeStateConfirmation()

    checks = make_checks()
    checks = [
        check
        for check in checks
        if check.name != "watchdog"
    ]

    with pytest.raises(SafeStateError):
        checker.confirm(checks)


def test_empty_checks_are_rejected():
    checker = SafeStateConfirmation()

    with pytest.raises(SafeStateError):
        checker.confirm([])


def test_checks_must_be_list_or_tuple():
    checker = SafeStateConfirmation()

    with pytest.raises(TypeError):
        checker.confirm(
            {
                "workspace": True
            }
        )


def test_every_item_must_be_safety_check():
    checker = SafeStateConfirmation()

    checks = make_checks()
    checks[0] = "invalid"

    with pytest.raises(TypeError):
        checker.confirm(checks)


def test_empty_check_name_is_rejected():
    checker = SafeStateConfirmation()

    checks = make_checks()
    checks[0] = SafetyCheck(
        name="   ",
        passed=True,
        message="OK",
    )

    with pytest.raises(ValueError):
        checker.confirm(checks)


def test_duplicate_check_names_are_rejected():
    checker = SafeStateConfirmation()

    checks = make_checks()
    checks.append(
        SafetyCheck(
            name="workspace",
            passed=True,
            message="duplicate",
        )
    )

    with pytest.raises(ValueError):
        checker.confirm(checks)


def test_require_safe_returns_report_when_safe():
    checker = SafeStateConfirmation()

    report = checker.require_safe(
        make_checks()
    )

    assert report.safe is True


def test_require_safe_raises_when_unsafe():
    checker = SafeStateConfirmation()

    checks = make_checks()

    checks[0] = SafetyCheck(
        name=checks[0].name,
        passed=False,
        message="failed",
    )

    with pytest.raises(SafeStateError):
        checker.require_safe(checks)


def test_is_safe_returns_true_for_safe_state():
    checker = SafeStateConfirmation()

    assert checker.is_safe(
        make_checks()
    ) is True


def test_is_safe_returns_false_for_unsafe_state():
    checker = SafeStateConfirmation()

    checks = make_checks()

    checks[0] = SafetyCheck(
        name=checks[0].name,
        passed=False,
        message="failed",
    )

    assert checker.is_safe(checks) is False


def test_is_safe_returns_false_for_missing_checks():
    checker = SafeStateConfirmation()

    assert checker.is_safe([]) is False


def test_report_is_saved():
    checker = SafeStateConfirmation()

    report = checker.confirm(
        make_checks()
    )

    assert checker.report == report


def test_checks_are_sorted_deterministically():
    checker = SafeStateConfirmation()

    checks = list(reversed(make_checks()))

    report = checker.confirm(checks)

    names = [
        check.name
        for check in report.checks
    ]

    assert names == sorted(names)


def test_same_checks_produce_same_report():
    checker = SafeStateConfirmation()

    first = checker.confirm(
        make_checks()
    )

    second = checker.confirm(
        make_checks()
    )

    assert first == second


def test_failed_names_are_reported():
    checker = SafeStateConfirmation()

    checks = make_checks()

    checks[0] = SafetyCheck(
        name=checks[0].name,
        passed=False,
        message="failure",
    )

    checks[1] = SafetyCheck(
        name=checks[1].name,
        passed=False,
        message="failure",
    )

    with pytest.raises(SafeStateError) as error:
        checker.require_safe(checks)

    assert checks[0].name in str(error.value)
    assert checks[1].name in str(error.value)


def test_check_message_is_preserved():
    checker = SafeStateConfirmation()

    checks = make_checks()

    checks[0] = SafetyCheck(
        name=checks[0].name,
        passed=True,
        message="workspace verified",
    )

    report = checker.confirm(checks)

    matching = next(
        check
        for check in report.checks
        if check.name == checks[0].name
    )

    assert matching.message == "workspace verified"
