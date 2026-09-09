import pytest

from sentinelshield.minor_version_candidate_detection import (
    MinorVersionCandidate,
    MinorVersionCandidateDetectionResult,
    detect_minor_version_candidates,
    minor_version_candidate_detection,
)


def test_minor_upgrade_is_detected():
    result = detect_minor_version_candidates(
        "requests",
        "2.28.3",
        ["2.29.0", "2.30.1", "3.0.0"],
    )

    assert result.total == 2
    assert [item.version for item in result.candidates] == [
        "2.29.0",
        "2.30.1",
    ]


def test_patch_upgrade_is_excluded():
    result = detect_minor_version_candidates(
        "pkg",
        "1.2.3",
        ["1.2.4", "1.2.9"],
    )

    assert result.candidates == ()
    assert result.total == 0


def test_major_upgrade_is_excluded():
    result = detect_minor_version_candidates(
        "pkg",
        "1.2.3",
        ["2.0.0", "3.1.0"],
    )

    assert result.candidates == ()
    assert result.total == 0


def test_older_and_same_minor_versions_are_excluded():
    result = detect_minor_version_candidates(
        "pkg",
        "2.4.5",
        [
            "2.3.9",
            "2.4.6",
            "2.4.5",
            "2.4.0",
        ],
    )

    assert result.candidates == ()
    assert result.total == 0


def test_minor_version_can_have_any_patch_value():
    result = detect_minor_version_candidates(
        "pkg",
        "1.2.7",
        ["1.3.0", "1.3.5", "1.3.99"],
    )

    assert [item.version for item in result.candidates] == [
        "1.3.0",
        "1.3.5",
        "1.3.99",
    ]


def test_multiple_minor_distances_are_ordered():
    result = detect_minor_version_candidates(
        "pkg",
        "1.2.0",
        ["1.5.0", "1.3.4", "1.4.0", "1.3.1"],
    )

    assert [item.version for item in result.candidates] == [
        "1.3.1",
        "1.3.4",
        "1.4.0",
        "1.5.0",
    ]


def test_duplicate_versions_are_removed():
    result = detect_minor_version_candidates(
        "pkg",
        "1.0.0",
        ["1.1.0", "1.1.0", "1.2.0", "1.2.0"],
    )

    assert [item.version for item in result.candidates] == [
        "1.1.0",
        "1.2.0",
    ]
    assert result.total == 2


def test_v_prefix_is_supported():
    result = detect_minor_version_candidates(
        "pkg",
        "v1.2.3",
        ["v1.3.0"],
    )

    assert result.total == 1
    assert result.candidates[0].version == "v1.3.0"


def test_prerelease_and_build_suffixes_are_accepted():
    result = detect_minor_version_candidates(
        "pkg",
        "1.2.3",
        ["1.3.0-alpha", "1.4.0+build1"],
    )

    assert [item.version for item in result.candidates] == [
        "1.3.0-alpha",
        "1.4.0+build1",
    ]


def test_candidate_metadata_is_correct():
    result = detect_minor_version_candidates(
        "pkg",
        "1.2.3",
        ["1.4.7"],
    )

    candidate = result.candidates[0]

    assert isinstance(candidate, MinorVersionCandidate)
    assert candidate.original_index == 0
    assert candidate.major == 1
    assert candidate.minor == 4
    assert candidate.patch == 7
    assert candidate.minor_distance == 2
    assert candidate.is_minor_upgrade is True


def test_result_metadata_is_correct():
    result = detect_minor_version_candidates(
        "pkg",
        "1.2.3",
        ["1.3.0", "2.0.0"],
    )

    assert isinstance(result, MinorVersionCandidateDetectionResult)
    assert result.package_name == "pkg"
    assert result.current_version == "1.2.3"
    assert result.total == 1


def test_input_order_does_not_change_semantic_order():
    first = detect_minor_version_candidates(
        "pkg",
        "1.2.0",
        ["1.4.0", "1.3.0"],
    )

    second = detect_minor_version_candidates(
        "pkg",
        "1.2.0",
        ["1.3.0", "1.4.0"],
    )

    assert [x.version for x in first.candidates] == [
        "1.3.0",
        "1.4.0",
    ]
    assert [x.version for x in second.candidates] == [
        "1.3.0",
        "1.4.0",
    ]


def test_none_current_version_is_rejected():
    with pytest.raises(TypeError, match="CURRENT_VERSION_MUST_BE_STRING"):
        detect_minor_version_candidates("pkg", None, ["1.1.0"])


def test_none_fixed_versions_is_rejected():
    with pytest.raises(TypeError, match="FIXED_VERSIONS_MUST_NOT_BE_NONE"):
        detect_minor_version_candidates("pkg", "1.0.0", None)


def test_string_fixed_versions_is_rejected():
    with pytest.raises(
        TypeError,
        match="FIXED_VERSIONS_MUST_BE_ITERABLE_OF_STRINGS",
    ):
        detect_minor_version_candidates("pkg", "1.0.0", "1.1.0")


def test_invalid_version_is_rejected():
    with pytest.raises(ValueError, match="VERSION_MUST_HAVE_MAJOR_MINOR_PATCH"):
        detect_minor_version_candidates("pkg", "1.0", ["1.1.0"])


def test_invalid_candidate_type_is_rejected():
    with pytest.raises(TypeError, match="VERSION_MUST_BE_STRING"):
        detect_minor_version_candidates("pkg", "1.0.0", ["1.1.0", 2])


def test_public_alias_points_to_same_function():
    assert minor_version_candidate_detection is detect_minor_version_candidates


def test_input_sequence_is_not_mutated():
    versions = ["1.4.0", "1.3.0", "2.0.0"]
    original = versions.copy()

    detect_minor_version_candidates(
        "pkg",
        "1.2.0",
        versions,
    )

    assert versions == original
