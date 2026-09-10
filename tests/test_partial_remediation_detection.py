import json

import pytest

from sentinelshield.partial_remediation_detection import (
    PartialRemediationDetectionError,
    PartialRemediationResult,
    RemediationState,
    detect_partial_remediation,
    validate_partial_remediation,
)


def test_no_change():
    result = detect_partial_remediation([], [])

    assert result.state is RemediationState.NO_CHANGE
    assert result.expected_changes == frozenset()
    assert result.actual_changes == frozenset()
    assert result.applied_changes == frozenset()
    assert result.missing_changes == frozenset()
    assert result.unexpected_changes == frozenset()


def test_complete_remediation():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
            "package-lock.json",
        ],
    )

    assert result.state is RemediationState.COMPLETE
    assert result.is_complete is True
    assert result.is_partial is False
    assert result.is_safe is True

    assert result.applied_changes == {
        "package.json",
        "package-lock.json",
    }

    assert result.missing_changes == frozenset()
    assert result.unexpected_changes == frozenset()


def test_partial_remediation_one_of_two_changes():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
        ],
    )

    assert result.state is RemediationState.PARTIAL
    assert result.is_partial is True
    assert result.is_complete is False
    assert result.is_safe is True

    assert result.applied_changes == {
        "package.json",
    }

    assert result.missing_changes == {
        "package-lock.json",
    }

    assert result.unexpected_changes == frozenset()


def test_partial_remediation_multiple_missing_changes():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
            "package-lock.json",
            "src/app.py",
        ],
        actual_changes=[
            "package.json",
        ],
    )

    assert result.state is RemediationState.PARTIAL

    assert result.applied_changes == {
        "package.json",
    }

    assert result.missing_changes == {
        "package-lock.json",
        "src/app.py",
    }


def test_unexpected_change_is_detected():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
        ],
        actual_changes=[
            "package.json",
            "README.md",
        ],
    )

    assert result.state is RemediationState.UNEXPECTED_CHANGE
    assert result.unexpected_changes == {"README.md"}
    assert result.applied_changes == {"package.json"}
    assert result.missing_changes == frozenset()
    assert result.is_safe is False


def test_only_unexpected_change():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
        ],
        actual_changes=[
            "README.md",
        ],
    )

    assert result.state is RemediationState.UNEXPECTED_CHANGE
    assert result.applied_changes == frozenset()
    assert result.missing_changes == {"package.json"}
    assert result.unexpected_changes == {"README.md"}


def test_failure_category_is_preserved():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
        ],
        failure_category="NON_ZERO_EXIT",
    )

    assert result.state is RemediationState.PARTIAL
    assert result.failure_category == "NON_ZERO_EXIT"


def test_generator_input_is_supported():
    result = detect_partial_remediation(
        (item for item in ["package.json"]),
        (item for item in ["package.json"]),
    )

    assert result.state is RemediationState.COMPLETE


def test_duplicate_paths_are_deduplicated():
    result = detect_partial_remediation(
        [
            "package.json",
            "package.json",
        ],
        [
            "package.json",
            "package.json",
        ],
    )

    assert result.state is RemediationState.COMPLETE
    assert result.applied_changes == {"package.json"}


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        " ",
        "/absolute/path",
        "../outside",
        "src/../../outside",
        ".",
        "./",
        None,
        123,
        b"package.json",
    ],
)
def test_invalid_paths_are_rejected(bad_path):
    with pytest.raises(PartialRemediationDetectionError):
        detect_partial_remediation(
            [bad_path],
            [],
        )


def test_string_collection_is_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        detect_partial_remediation(
            "package.json",
            [],
        )


def test_bytes_collection_is_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        detect_partial_remediation(
            b"package.json",
            [],
        )


def test_invalid_actual_collection_is_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        detect_partial_remediation(
            [],
            "package.json",
        )


def test_serialization():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
        ],
    )

    payload = json.loads(result.to_json())

    assert payload["state"] == "PARTIAL"
    assert payload["expected_changes"] == [
        "package-lock.json",
        "package.json",
    ]
    assert payload["actual_changes"] == [
        "package.json",
    ]
    assert payload["applied_changes"] == [
        "package.json",
    ]
    assert payload["missing_changes"] == [
        "package-lock.json",
    ]
    assert payload["unexpected_changes"] == []
    assert payload["is_partial"] is True
    assert payload["is_complete"] is False
    assert payload["is_safe"] is True


def test_validation_accepts_valid_result():
    result = detect_partial_remediation(
        ["package.json"],
        ["package.json"],
    )

    assert validate_partial_remediation(result) is True


@pytest.mark.parametrize(
    "invalid_value",
    [
        None,
        {},
        [],
        "result",
        123,
    ],
)
def test_validation_rejects_invalid_objects(invalid_value):
    assert validate_partial_remediation(invalid_value) is False


def test_inconsistent_result_is_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        PartialRemediationResult(
            state=RemediationState.COMPLETE,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset(),
            applied_changes=frozenset(),
            missing_changes=frozenset({"package.json"}),
            unexpected_changes=frozenset(),
        )


def test_inconsistent_applied_changes_are_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        PartialRemediationResult(
            state=RemediationState.PARTIAL,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset(),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset({"package.json"}),
            unexpected_changes=frozenset(),
        )


def test_inconsistent_unexpected_changes_are_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        PartialRemediationResult(
            state=RemediationState.COMPLETE,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset({"package.json", "README.md"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
        )


def test_unexpected_state_requires_actual_unexpected_change():
    with pytest.raises(PartialRemediationDetectionError):
        PartialRemediationResult(
            state=RemediationState.UNEXPECTED_CHANGE,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
        )


def test_complete_requires_all_expected_changes():
    with pytest.raises(PartialRemediationDetectionError):
        PartialRemediationResult(
            state=RemediationState.COMPLETE,
            expected_changes=frozenset(
                {
                    "package.json",
                    "package-lock.json",
                }
            ),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset({"package-lock.json"}),
            unexpected_changes=frozenset(),
        )


def test_partial_does_not_hide_unexpected_changes():
    result = detect_partial_remediation(
        expected_changes=[
            "package.json",
            "package-lock.json",
        ],
        actual_changes=[
            "package.json",
            "README.md",
        ],
    )

    assert result.state is RemediationState.UNEXPECTED_CHANGE
    assert result.missing_changes == {"package-lock.json"}
    assert result.unexpected_changes == {"README.md"}
    assert result.is_safe is False
