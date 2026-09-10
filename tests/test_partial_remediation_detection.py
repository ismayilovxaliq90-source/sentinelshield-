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
    assert result.is_safe
    assert not result.is_partial


def test_complete_remediation():
    result = detect_partial_remediation(
        ["package.json", "package-lock.json"],
        ["package.json", "package-lock.json"],
    )

    assert result.state is RemediationState.COMPLETE
    assert result.is_complete
    assert result.applied_changes == {
        "package.json",
        "package-lock.json",
    }
    assert not result.missing_changes


def test_partial_remediation():
    result = detect_partial_remediation(
        ["package.json", "package-lock.json"],
        ["package.json"],
    )

    assert result.state is RemediationState.PARTIAL
    assert result.is_partial
    assert result.applied_changes == {"package.json"}
    assert result.missing_changes == {"package-lock.json"}
    assert not result.unexpected_changes


def test_unexpected_change():
    result = detect_partial_remediation(
        ["package.json"],
        ["package.json", "README.md"],
    )

    assert result.state is RemediationState.UNEXPECTED_CHANGE
    assert result.unexpected_changes == {"README.md"}
    assert not result.is_safe


def test_expected_and_actual_empty():
    result = detect_partial_remediation([], [])

    assert result.to_dict()["state"] == "NO_CHANGE"


def test_failure_category_is_preserved():
    result = detect_partial_remediation(
        ["package.json", "package-lock.json"],
        ["package.json"],
        failure_category="NON_ZERO_EXIT",
    )

    assert result.failure_category == "NON_ZERO_EXIT"
    assert result.state is RemediationState.PARTIAL


def test_paths_are_normalized():
    result = detect_partial_remediation(
        ["src/package.json"],
        ["src/package.json"],
    )

    assert result.state is RemediationState.COMPLETE


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        " ",
        "/absolute/path",
        "../outside",
        "a/../../outside",
        None,
        123,
    ],
)
def test_invalid_path_rejected(bad_path):
    with pytest.raises(PartialRemediationDetectionError):
        detect_partial_remediation([bad_path], [])


def test_string_collection_is_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        detect_partial_remediation("package.json", [])


def test_result_serialization():
    result = detect_partial_remediation(
        ["package.json", "package-lock.json"],
        ["package.json"],
    )

    payload = json.loads(result.to_json())

    assert payload["state"] == "PARTIAL"
    assert payload["is_partial"] is True
    assert payload["missing_changes"] == ["package-lock.json"]


def test_validation_accepts_valid_result():
    result = detect_partial_remediation(
        ["package.json"],
        ["package.json"],
    )

    assert validate_partial_remediation(result) is True


def test_validation_rejects_non_result():
    assert validate_partial_remediation(None) is False
    assert validate_partial_remediation({}) is False


def test_inconsistent_result_rejected():
    with pytest.raises(PartialRemediationDetectionError):
        PartialRemediationResult(
            state=RemediationState.COMPLETE,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset(),
            applied_changes=frozenset(),
            missing_changes=frozenset({"package.json"}),
            unexpected_changes=frozenset(),
        )


def test_unexpected_state_requires_unexpected_changes():
    with pytest.raises(PartialRemediationDetectionError):
        PartialRemediationResult(
            state=RemediationState.UNEXPECTED_CHANGE,
            expected_changes=frozenset({"package.json"}),
            actual_changes=frozenset({"package.json"}),
            applied_changes=frozenset({"package.json"}),
            missing_changes=frozenset(),
            unexpected_changes=frozenset(),
        )
