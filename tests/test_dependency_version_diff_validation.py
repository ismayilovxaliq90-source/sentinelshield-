from dataclasses import FrozenInstanceError

from sentinelshield.dependency_version_diff_validation import (
    DependencyVersionDiffResult,
    validate_dependency_version_diff,
    validate_dependency_versions,
)


def test_no_changes():
    inventory = {
        "requests": "2.31.0",
        "urllib3": "2.0.7",
    }

    result = validate_dependency_version_diff(
        inventory,
        inventory,
    )

    assert isinstance(
        result,
        DependencyVersionDiffResult,
    )

    assert result.changed == ()
    assert result.added == ()
    assert result.removed == ()
    assert result.unexpected == ()
    assert result.status == "NO_CHANGES"
    assert result.reason == (
        "NO_DEPENDENCY_VERSION_CHANGES"
    )


def test_approved_version_change():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    assert result.changed == ("requests",)
    assert result.added == ()
    assert result.removed == ()
    assert result.unexpected == ()
    assert result.status == "VALIDATED"
    assert result.reason == (
        "DEPENDENCY_VERSION_DIFF_VALIDATED"
    )


def test_unexpected_version_change():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.33.0"},
        {"requests": "2.32.0"},
    )

    assert result.changed == ("requests",)
    assert result.unexpected == ("requests",)
    assert result.status == "UNEXPECTED_CHANGES"


def test_changed_dependency_without_approval():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
    )

    assert result.changed == ("requests",)
    assert result.unexpected == ("requests",)


def test_added_dependency_with_approval():
    result = validate_dependency_version_diff(
        {},
        {"urllib3": "2.0.7"},
        {"urllib3": "2.0.7"},
    )

    assert result.changed == ()
    assert result.added == ("urllib3",)
    assert result.removed == ()
    assert result.unexpected == ()
    assert result.status == "VALIDATED"


def test_added_dependency_without_approval():
    result = validate_dependency_version_diff(
        {},
        {"urllib3": "2.0.7"},
    )

    assert result.added == ("urllib3",)
    assert result.unexpected == ("urllib3",)
    assert result.status == "UNEXPECTED_CHANGES"


def test_added_dependency_wrong_version():
    result = validate_dependency_version_diff(
        {},
        {"urllib3": "2.1.0"},
        {"urllib3": "2.0.7"},
    )

    assert result.added == ("urllib3",)
    assert result.unexpected == ("urllib3",)


def test_removed_dependency_is_detected():
    result = validate_dependency_version_diff(
        {
            "requests": "2.31.0",
            "urllib3": "2.0.7",
        },
        {
            "requests": "2.31.0",
        },
    )

    assert result.changed == ()
    assert result.added == ()
    assert result.removed == ("urllib3",)
    assert result.unexpected == ("urllib3",)
    assert result.status == "UNEXPECTED_CHANGES"


def test_multiple_changes_are_deterministic():
    result = validate_dependency_version_diff(
        {
            "zeta": "1.0",
            "alpha": "1.0",
            "middle": "1.0",
        },
        {
            "zeta": "2.0",
            "alpha": "1.0",
            "new": "1.0",
        },
        {
            "zeta": "2.0",
            "new": "1.0",
        },
    )

    assert result.changed == ("zeta",)
    assert result.added == ("new",)
    assert result.removed == ("middle",)
    assert result.unexpected == ("middle",)


def test_invalid_baseline():
    result = validate_dependency_version_diff(
        None,
        {},
    )

    assert result.status == "INVALID_INPUT"
    assert result.reason == (
        "INVENTORY_MUST_BE_MAPPING"
    )


def test_invalid_current():
    result = validate_dependency_version_diff(
        {},
        None,
    )

    assert result.status == "INVALID_INPUT"


def test_invalid_dependency_name():
    result = validate_dependency_version_diff(
        {"": "1.0"},
        {},
    )

    assert result.status == "INVALID_INPUT"


def test_invalid_dependency_version():
    result = validate_dependency_version_diff(
        {"requests": ""},
        {},
    )

    assert result.status == "INVALID_INPUT"


def test_non_string_dependency_name():
    result = validate_dependency_version_diff(
        {123: "1.0"},
        {},
    )

    assert result.status == "INVALID_INPUT"


def test_non_string_dependency_version():
    result = validate_dependency_version_diff(
        {"requests": 123},
        {},
    )

    assert result.status == "INVALID_INPUT"


def test_invalid_expected_scope():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        [],
    )

    assert result.status == "INVALID_INPUT"


def test_invalid_expected_dependency():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"": "2.32.0"},
    )

    assert result.status == "INVALID_INPUT"


def test_invalid_expected_version():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": ""},
    )

    assert result.status == "INVALID_INPUT"


def test_whitespace_is_normalized():
    result = validate_dependency_version_diff(
        {" requests ": " 2.31.0 "},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    assert result.changed == ("requests",)
    assert result.unexpected == ()
    assert result.status == "VALIDATED"


def test_inputs_are_not_mutated():
    baseline = {
        "requests": "2.31.0",
    }

    current = {
        "requests": "2.32.0",
    }

    expected = {
        "requests": "2.32.0",
    }

    baseline_before = baseline.copy()
    current_before = current.copy()
    expected_before = expected.copy()

    validate_dependency_version_diff(
        baseline,
        current,
        expected,
    )

    assert baseline == baseline_before
    assert current == current_before
    assert expected == expected_before


def test_result_is_immutable():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    try:
        result.status = "BROKEN"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError(
            "DependencyVersionDiffResult must be immutable"
        )


def test_compatibility_wrapper():
    result = validate_dependency_versions(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    assert result.changed == ("requests",)
    assert result.unexpected == ()
    assert result.status == "VALIDATED"


def test_unchanged_dependency_not_reported():
    result = validate_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.31.0"},
    )

    assert "requests" not in result.changed
    assert "requests" not in result.added
    assert "requests" not in result.removed
    assert "requests" not in result.unexpected


def test_mixed_valid_and_unexpected_changes():
    result = validate_dependency_version_diff(
        {
            "requests": "2.31.0",
            "urllib3": "2.0.7",
        },
        {
            "requests": "2.32.0",
            "urllib3": "2.1.0",
        },
        {
            "requests": "2.32.0",
        },
    )

    assert result.changed == (
        "requests",
        "urllib3",
    )

    assert result.unexpected == (
        "urllib3",
    )

    assert result.status == "UNEXPECTED_CHANGES"
