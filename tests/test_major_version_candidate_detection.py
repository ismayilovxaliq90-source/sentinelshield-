import pytest

from sentinelshield.major_version_candidate_detection import (
    MajorVersionCandidate,
    MajorVersionCandidateDetectionResult,
    detect_major_version_candidate,
    detect_major_version_candidates,
    major_version_candidate_detection,
)


def test_major_upgrade_is_detected():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        ["2.0.0", "3.0.0"],
    )

    assert [x.version for x in result.candidates] == [
        "2.0.0",
        "3.0.0",
    ]


def test_minor_upgrade_is_excluded():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        ["1.3.0", "1.9.9"],
    )

    assert result.total == 0


def test_patch_upgrade_is_excluded():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        ["1.2.4", "1.2.9"],
    )

    assert result.total == 0


def test_same_version_is_excluded():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        ["1.2.3"],
    )

    assert result.total == 0


def test_older_major_is_excluded():
    result = detect_major_version_candidates(
        "pkg",
        "2.2.3",
        ["1.9.9"],
    )

    assert result.total == 0


def test_mixed_versions_are_filtered():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        [
            "1.3.0",
            "2.0.0",
            "1.2.4",
            "3.1.0",
            "2.5.7",
            "0.9.9",
        ],
    )

    assert [x.version for x in result.candidates] == [
        "2.0.0",
        "2.5.7",
        "3.1.0",
    ]


def test_closest_major_is_first():
    result = detect_major_version_candidates(
        "pkg",
        "1.0.0",
        ["4.0.0", "3.0.0", "2.5.0"],
    )

    assert [x.version for x in result.candidates] == [
        "2.5.0",
        "3.0.0",
        "4.0.0",
    ]


def test_same_major_candidates_are_not_major_upgrades():
    result = detect_major_version_candidates(
        "pkg",
        "2.4.5",
        ["2.5.0", "2.9.9", "2.4.6"],
    )

    assert result.candidates == ()


def test_duplicate_versions_are_removed():
    result = detect_major_version_candidates(
        "pkg",
        "1.0.0",
        ["2.0.0", "2.0.0", "3.0.0", "3.0.0"],
    )

    assert [x.version for x in result.candidates] == [
        "2.0.0",
        "3.0.0",
    ]
    assert result.total == 2


def test_v_prefix_is_supported():
    result = detect_major_version_candidates(
        "pkg",
        "v1.2.3",
        ["v2.0.0", "v1.3.0"],
    )

    assert [x.version for x in result.candidates] == ["v2.0.0"]


def test_suffixes_are_supported():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        ["2.0.0-alpha", "3.0.0+build1"],
    )

    assert [x.version for x in result.candidates] == [
        "2.0.0-alpha",
        "3.0.0+build1",
    ]


def test_candidate_metadata():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        ["3.4.7"],
    )

    candidate = result.candidates[0]

    assert isinstance(candidate, MajorVersionCandidate)
    assert candidate.version == "3.4.7"
    assert candidate.original_index == 0
    assert candidate.major == 3
    assert candidate.minor == 4
    assert candidate.patch == 7
    assert candidate.major_distance == 2
    assert candidate.is_major_upgrade is True


def test_result_metadata():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        ["2.0.0"],
    )

    assert isinstance(result, MajorVersionCandidateDetectionResult)
    assert result.package_name == "pkg"
    assert result.current_version == "1.2.3"
    assert result.total == 1


def test_input_is_not_mutated():
    versions = ["3.0.0", "2.0.0", "1.3.0"]
    original = versions.copy()

    detect_major_version_candidates(
        "pkg",
        "1.2.3",
        versions,
    )

    assert versions == original


def test_none_current_version_rejected():
    with pytest.raises(TypeError, match="CURRENT_VERSION_MUST_BE_STRING"):
        detect_major_version_candidates("pkg", None, ["2.0.0"])


def test_none_candidates_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_NOT_BE_NONE",
    ):
        detect_major_version_candidates("pkg", "1.2.3", None)


def test_string_candidates_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_ITERABLE_OF_STRINGS",
    ):
        detect_major_version_candidates("pkg", "1.2.3", "2.0.0")


def test_invalid_current_version_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_MUST_HAVE_MAJOR_MINOR_PATCH",
    ):
        detect_major_version_candidates("pkg", "1.2", ["2.0.0"])


def test_invalid_candidate_version_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_MUST_HAVE_MAJOR_MINOR_PATCH",
    ):
        detect_major_version_candidates("pkg", "1.2.3", ["2.0"])


def test_non_string_candidate_rejected():
    with pytest.raises(TypeError, match="VERSION_MUST_BE_STRING"):
        detect_major_version_candidates("pkg", "1.2.3", ["2.0.0", 2])


def test_public_aliases():
    assert major_version_candidate_detection is detect_major_version_candidates
    assert detect_major_version_candidate is detect_major_version_candidates


def test_empty_candidates():
    result = detect_major_version_candidates(
        "pkg",
        "1.2.3",
        [],
    )

    assert result.total == 0
    assert result.candidates == ()
