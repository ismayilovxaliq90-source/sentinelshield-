import pytest

from sentinelshield.breaking_change_detection import (
    BreakingChangeAssessment,
    BreakingChangeDetectionInput,
    BreakingChangeDetectionResult,
    breaking_change_detection,
    detect_breaking_change,
    detect_breaking_changes,
)


def test_major_change_is_breaking():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["2.0.0"],
    )

    item = result.assessments[0]

    assert item.breaking_change is True
    assert item.change_type == "MAJOR"
    assert item.reason == "MAJOR_VERSION_CHANGE"


def test_minor_change_is_non_breaking():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["1.3.0"],
    )

    item = result.assessments[0]

    assert item.breaking_change is False
    assert item.change_type == "MINOR"
    assert item.reason == "MINOR_VERSION_CHANGE"


def test_patch_change_is_non_breaking():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["1.2.4"],
    )

    item = result.assessments[0]

    assert item.breaking_change is False
    assert item.change_type == "PATCH"
    assert item.reason == "PATCH_VERSION_CHANGE"


def test_no_change_is_non_breaking():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["1.2.3"],
    )

    item = result.assessments[0]

    assert item.breaking_change is False
    assert item.change_type == "NONE"
    assert item.reason == "NO_VERSION_CHANGE"


def test_major_minor_patch_flags():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["2.4.5"],
    )

    item = result.assessments[0]

    assert item.major_changed is True
    assert item.minor_changed is True
    assert item.patch_changed is True


def test_minor_only_flags():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["1.4.3"],
    )

    item = result.assessments[0]

    assert item.major_changed is False
    assert item.minor_changed is True
    assert item.patch_changed is False


def test_patch_only_flags():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["1.2.7"],
    )

    item = result.assessments[0]

    assert item.major_changed is False
    assert item.minor_changed is False
    assert item.patch_changed is True


def test_mixed_candidates_are_classified():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["1.2.4", "1.3.0", "2.0.0"],
    )

    assert result.total == 3
    assert result.breaking_count == 1
    assert result.non_breaking_count == 2


def test_breaking_candidates_are_sorted_after_non_breaking():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["2.0.0", "1.3.0", "1.2.4"],
    )

    assert [item.candidate_version for item in result.assessments] == [
        "1.2.4",
        "1.3.0",
        "2.0.0",
    ]


def test_duplicate_versions_are_removed():
    result = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["2.0.0", "v2.0.0", "1.3.0"],
    )

    assert result.total == 2


def test_version_suffixes_are_supported():
    result = detect_breaking_changes(
        "demo",
        "v1.2.3",
        ["1.2.4-beta", "1.3.0+build"],
    )

    assert result.total == 2
    assert result.assessments[0].breaking_change is False


def test_partial_versions_are_supported():
    result = detect_breaking_changes(
        "demo",
        "1.2",
        ["2", "1.3"],
    )

    assert result.total == 2
    assert result.breaking_count == 1


def test_metadata_is_preserved():
    result = detect_breaking_changes(
        "requests",
        "2.31.0",
        ["2.32.0"],
        vulnerability_id="CVE-TEST",
    )

    item = result.assessments[0]

    assert item.package_name == "requests"
    assert item.current_version == "2.31.0"
    assert item.candidate_version == "2.32.0"


def test_original_index_is_preserved():
    result = detect_breaking_changes(
        "demo",
        "1.0.0",
        ["2.0.0", "1.1.0"],
    )

    by_version = {
        item.candidate_version: item
        for item in result.assessments
    }

    assert by_version["2.0.0"].original_index == 0
    assert by_version["1.1.0"].original_index == 1


def test_empty_candidates():
    result = detect_breaking_changes(
        "demo",
        "1.0.0",
        [],
    )

    assert result.assessments == ()
    assert result.total == 0
    assert result.breaking_count == 0
    assert result.non_breaking_count == 0


def test_invalid_package_name_type():
    with pytest.raises(
        TypeError,
        match="PACKAGE_NAME_MUST_BE_STRING",
    ):
        detect_breaking_changes(
            123,
            "1.0.0",
            ["1.1.0"],
        )


def test_empty_package_name():
    with pytest.raises(
        ValueError,
        match="PACKAGE_NAME_IS_EMPTY",
    ):
        detect_breaking_changes(
            " ",
            "1.0.0",
            ["1.1.0"],
        )


def test_invalid_current_version_type():
    with pytest.raises(
        TypeError,
        match="CURRENT_VERSION_MUST_BE_STRING",
    ):
        detect_breaking_changes(
            "demo",
            100,
            ["1.1.0"],
        )


def test_invalid_current_version():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        detect_breaking_changes(
            "demo",
            "1.x.0",
            ["1.1.0"],
        )


def test_invalid_candidate_version():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        detect_breaking_changes(
            "demo",
            "1.0.0",
            ["2.x.0"],
        )


def test_invalid_candidate_type():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING:0",
    ):
        detect_breaking_changes(
            "demo",
            "1.0.0",
            [123],
        )


def test_invalid_candidate_collection():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_SEQUENCE",
    ):
        detect_breaking_changes(
            "demo",
            "1.0.0",
            None,
        )


def test_string_candidate_collection_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_SEQUENCE",
    ):
        detect_breaking_changes(
            "demo",
            "1.0.0",
            "2.0.0",
        )


def test_invalid_vulnerability_id():
    with pytest.raises(
        TypeError,
        match="VULNERABILITY_ID_MUST_BE_STRING_OR_NONE",
    ):
        detect_breaking_changes(
            "demo",
            "1.0.0",
            ["1.1.0"],
            vulnerability_id=123,
        )


def test_dataclasses():
    result = detect_breaking_changes(
        "demo",
        "1.0.0",
        ["1.1.0"],
    )

    assert isinstance(result, BreakingChangeDetectionResult)
    assert isinstance(
        result.assessments[0],
        BreakingChangeAssessment,
    )

    value = BreakingChangeDetectionInput(
        package_name="demo",
        current_version="1.0.0",
        candidate_versions=["1.1.0"],
    )

    assert value.package_name == "demo"


def test_public_aliases():
    assert (
        breaking_change_detection
        is detect_breaking_changes
    )

    assert (
        detect_breaking_change
        is detect_breaking_changes
    )


def test_deterministic_result():
    first = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["2.0.0", "1.3.0", "1.2.4"],
    )

    second = detect_breaking_changes(
        "demo",
        "1.2.3",
        ["2.0.0", "1.3.0", "1.2.4"],
    )

    assert first == second


def test_input_is_not_modified():
    versions = ["2.0.0", "1.3.0", "1.2.4"]
    original = versions.copy()

    detect_breaking_changes(
        "demo",
        "1.2.3",
        versions,
    )

    assert versions == original
