import pytest

from sentinelshield.transitive_remediation_candidate_generation import (
    TransitiveRemediationCandidate,
    TransitiveRemediationCandidateGenerationInput,
    TransitiveRemediationCandidateGenerationResult,
    generate_transitive_candidates,
    generate_transitive_remediation_candidates,
    transitive_remediation_candidate_generation,
)


def test_generates_upgrade_candidates():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo-package",
        "1.2.3",
        ["1.2.4", "1.3.0", "2.0.0"],
    )

    assert result.total == 3
    assert [c.candidate_version for c in result.candidates] == [
        "1.2.4",
        "1.3.0",
        "2.0.0",
    ]


def test_non_upgrade_versions_are_excluded():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo-package",
        "2.0.0",
        ["1.9.9", "2.0.0", "1.5.0"],
    )

    assert result.candidates == ()
    assert result.total == 0


def test_duplicates_are_removed():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo-package",
        "1.2.3",
        ["1.2.4", "1.2.4", "v1.2.4", "1.3.0"],
    )

    assert result.total == 2
    assert [
        _candidate.candidate_version
        for _candidate in result.candidates
    ] == ["1.2.4", "1.3.0"]


def test_transitive_flag_is_true():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo-package",
        "1.0.0",
        ["1.1.0"],
    )

    candidate = result.candidates[0]

    assert candidate.is_transitive is True
    assert candidate.is_upgrade is True


def test_metadata_is_preserved():
    result = generate_transitive_remediation_candidates(
        "CVE-123",
        "requests",
        "2.31.0",
        ["2.32.0"],
        source="lockfile",
    )

    candidate = result.candidates[0]

    assert candidate.vulnerability_id == "CVE-123"
    assert candidate.package_name == "requests"
    assert candidate.current_version == "2.31.0"
    assert candidate.candidate_version == "2.32.0"
    assert candidate.source == "lockfile"


def test_original_index_is_preserved():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.0.0",
        ["0.9.0", "1.2.0", "1.1.0"],
    )

    assert result.candidates[0].original_index == 2
    assert result.candidates[1].original_index == 1


def test_closest_upgrade_is_first():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.2.3",
        ["1.4.0", "1.2.5", "1.3.0", "2.0.0"],
    )

    assert [
        c.candidate_version for c in result.candidates
    ] == [
        "1.2.5",
        "1.3.0",
        "1.4.0",
        "2.0.0",
    ]


def test_major_upgrade_follows_minor_upgrades():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.9.9",
        ["2.0.0", "1.10.0", "1.9.10"],
    )

    assert [
        c.candidate_version for c in result.candidates
    ] == [
        "1.9.10",
        "1.10.0",
        "2.0.0",
    ]


def test_partial_versions_are_supported():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.2",
        ["1.3", "1.2.1"],
    )

    assert [
        c.candidate_version for c in result.candidates
    ] == [
        "1.2.1",
        "1.3",
    ]


def test_version_prefix_and_suffix_are_supported():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "v1.2.3",
        ["v1.2.4-beta", "1.3.0+build"],
    )

    assert result.total == 2


def test_none_vulnerability_id_is_allowed():
    result = generate_transitive_remediation_candidates(
        None,
        "demo",
        "1.0.0",
        ["1.1.0"],
    )

    assert result.candidates[0].vulnerability_id is None


def test_empty_candidate_list():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.0.0",
        [],
    )

    assert result.candidates == ()
    assert result.total == 0


def test_invalid_candidate_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        generate_transitive_remediation_candidates(
            "CVE-TEST",
            "demo",
            "1.0.0",
            ["1.x.0"],
        )


def test_invalid_current_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        generate_transitive_remediation_candidates(
            "CVE-TEST",
            "demo",
            "1.x.0",
            ["1.2.0"],
        )


def test_candidate_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING:0",
    ):
        generate_transitive_remediation_candidates(
            "CVE-TEST",
            "demo",
            "1.0.0",
            [120],
        )


def test_package_name_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="PACKAGE_NAME_MUST_BE_STRING",
    ):
        generate_transitive_remediation_candidates(
            "CVE-TEST",
            123,
            "1.0.0",
            ["1.1.0"],
        )


def test_candidate_versions_must_be_sequence():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_SEQUENCE",
    ):
        generate_transitive_remediation_candidates(
            "CVE-TEST",
            "demo",
            "1.0.0",
            None,
        )


def test_string_candidate_collection_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_SEQUENCE",
    ):
        generate_transitive_remediation_candidates(
            "CVE-TEST",
            "demo",
            "1.0.0",
            "1.1.0",
        )


def test_source_must_not_be_empty():
    with pytest.raises(
        ValueError,
        match="SOURCE_IS_EMPTY",
    ):
        generate_transitive_remediation_candidates(
            "CVE-TEST",
            "demo",
            "1.0.0",
            ["1.1.0"],
            source=" ",
        )


def test_result_dataclass():
    result = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.0.0",
        ["1.1.0"],
    )

    assert isinstance(
        result,
        TransitiveRemediationCandidateGenerationResult,
    )

    assert isinstance(
        result.candidates[0],
        TransitiveRemediationCandidate,
    )


def test_input_dataclass():
    value = TransitiveRemediationCandidateGenerationInput(
        vulnerability_id="CVE-TEST",
        package_name="demo",
        current_version="1.0.0",
        candidate_versions=["1.1.0"],
    )

    assert value.package_name == "demo"
    assert value.current_version == "1.0.0"
    assert value.candidate_versions == ["1.1.0"]
    assert value.source == "transitive"


def test_public_aliases():
    assert (
        transitive_remediation_candidate_generation
        is generate_transitive_remediation_candidates
    )

    assert (
        generate_transitive_candidates
        is generate_transitive_remediation_candidates
    )


def test_deterministic_result():
    first = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.2.3",
        ["2.0.0", "1.3.0", "1.2.4"],
    )

    second = generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.2.3",
        ["2.0.0", "1.3.0", "1.2.4"],
    )

    assert first == second


def test_input_collection_is_not_modified():
    versions = ["2.0.0", "1.3.0", "1.2.4"]
    original = versions.copy()

    generate_transitive_remediation_candidates(
        "CVE-TEST",
        "demo",
        "1.2.3",
        versions,
    )

    assert versions == original
