import pytest

from sentinelshield.compatible_version_discovery import (
    CompatibleVersionCandidate,
    CompatibleVersionDiscoveryResult,
    compatible_version_discovery,
    discover_compatible_version_candidates,
    discover_compatible_versions,
)


def test_patch_upgrade_is_compatible():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.2.4"],
    )

    assert [item.version for item in result.candidates] == ["1.2.4"]


def test_minor_upgrade_is_compatible():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.3.0", "1.4.0"],
    )

    assert [item.version for item in result.candidates] == [
        "1.3.0",
        "1.4.0",
    ]


def test_major_upgrade_is_not_compatible():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["2.0.0", "3.0.0"],
    )

    assert result.total == 0


def test_same_version_is_excluded():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.2.3"],
    )

    assert result.total == 0


def test_older_version_is_excluded():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.2.2", "1.1.9"],
    )

    assert result.total == 0


def test_mixed_candidates_are_filtered_correctly():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        [
            "2.0.0",
            "1.4.0",
            "1.2.4",
            "1.1.9",
            "3.0.0",
            "1.3.0",
        ],
    )

    assert [item.version for item in result.candidates] == [
        "1.2.4",
        "1.3.0",
        "1.4.0",
    ]


def test_closest_candidate_is_first():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.5.0", "1.2.5", "1.3.0"],
    )

    assert [item.version for item in result.candidates] == [
        "1.2.5",
        "1.3.0",
        "1.5.0",
    ]


def test_duplicate_candidates_are_removed():
    result = discover_compatible_versions(
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
    result = discover_compatible_versions(
        "pkg",
        "v1.2.3",
        ["v1.2.4", "v2.0.0"],
    )

    assert [item.version for item in result.candidates] == ["v1.2.4"]


def test_prerelease_and_build_suffixes_are_parsed():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.3.0-alpha", "1.4.0+build1", "2.0.0-beta"],
    )

    assert [item.version for item in result.candidates] == [
        "1.3.0-alpha",
        "1.4.0+build1",
    ]


def test_candidate_metadata():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.4.7"],
    )

    candidate = result.candidates[0]

    assert isinstance(candidate, CompatibleVersionCandidate)
    assert candidate.version == "1.4.7"
    assert candidate.original_index == 0
    assert candidate.major == 1
    assert candidate.minor == 4
    assert candidate.patch == 7
    assert candidate.distance == 2000004
    assert candidate.is_compatible is True


def test_result_metadata():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        ["1.3.0"],
    )

    assert isinstance(result, CompatibleVersionDiscoveryResult)
    assert result.package_name == "pkg"
    assert result.current_version == "1.2.3"
    assert result.total == 1


def test_input_is_not_mutated():
    versions = ["1.4.0", "1.2.4", "2.0.0"]
    original = versions.copy()

    discover_compatible_versions(
        "pkg",
        "1.2.3",
        versions,
    )

    assert versions == original


def test_none_current_version_rejected():
    with pytest.raises(TypeError, match="CURRENT_VERSION_MUST_BE_STRING"):
        discover_compatible_versions("pkg", None, ["1.3.0"])


def test_none_candidates_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_NOT_BE_NONE",
    ):
        discover_compatible_versions("pkg", "1.2.3", None)


def test_string_candidates_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_ITERABLE_OF_STRINGS",
    ):
        discover_compatible_versions("pkg", "1.2.3", "1.3.0")


def test_invalid_current_version_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_MUST_HAVE_MAJOR_MINOR_PATCH",
    ):
        discover_compatible_versions("pkg", "1.2", ["1.3.0"])


def test_invalid_candidate_version_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_MUST_HAVE_MAJOR_MINOR_PATCH",
    ):
        discover_compatible_versions("pkg", "1.2.3", ["1.3"])


def test_non_string_candidate_rejected():
    with pytest.raises(TypeError, match="VERSION_MUST_BE_STRING"):
        discover_compatible_versions("pkg", "1.2.3", ["1.3.0", 123])


def test_public_aliases():
    assert compatible_version_discovery is discover_compatible_versions
    assert (
        discover_compatible_version_candidates
        is discover_compatible_versions
    )


def test_empty_candidates():
    result = discover_compatible_versions(
        "pkg",
        "1.2.3",
        [],
    )

    assert result.total == 0
    assert result.candidates == ()
