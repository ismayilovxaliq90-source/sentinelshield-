import pytest

from sentinelshield.remediation_candidate_set import (
    RemediationCandidate,
    RemediationCandidateSet,
    RemediationCandidateSetInput,
    build_remediation_candidate_set,
    create_remediation_candidate_set,
    remediation_candidate_set,
)


def candidate(
    version="1.1.0",
    risk=20,
    *,
    compatibility=90,
    security=90,
    confidence=90,
    breaking=False,
    distance=1,
    index=0,
):
    return RemediationCandidate(
        package_name="demo",
        current_version="1.0.0",
        candidate_version=version,
        risk_score=risk,
        risk_level=(
            "LOW"
            if risk < 25
            else "MEDIUM"
            if risk < 50
            else "HIGH"
            if risk < 75
            else "CRITICAL"
        ),
        security_score=security,
        compatibility_score=compatibility,
        confidence_score=confidence,
        breaking_change=breaking,
        major_upgrade=breaking,
        minor_upgrade=not breaking,
        patch_upgrade=False,
        upgrade_distance=distance,
        original_index=index,
    )


def test_basic_candidate_set():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate("1.1.0", 20),
                candidate("1.2.0", 40, index=1),
            ]
        )
    )

    assert isinstance(result, RemediationCandidateSet)
    assert result.total == 2
    assert result.selected_count == 2


def test_lowest_risk_is_first():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate("1.2.0", 60, index=0),
                candidate("1.1.0", 10, index=1),
            ]
        )
    )

    assert (
        result.candidates[0].candidate_version
        == "1.1.0"
    )


def test_max_candidates_limits_set():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate("1.1.0", 10, index=0),
                candidate("1.2.0", 20, index=1),
                candidate("1.3.0", 30, index=2),
            ],
            max_candidates=2,
        )
    )

    assert result.total == 2
    assert result.selected_count == 2
    assert result.excluded_count == 1


def test_max_risk_score_filters_candidates():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate("1.1.0", 20, index=0),
                candidate("1.2.0", 60, index=1),
            ],
            max_risk_score=50,
        )
    )

    assert [
        item.risk_score
        for item in result.candidates
    ] == [20.0]


def test_breaking_changes_can_be_excluded():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "2.0.0",
                    30,
                    breaking=True,
                    index=0,
                ),
                candidate(
                    "1.1.0",
                    20,
                    breaking=False,
                    index=1,
                ),
            ],
            include_breaking_changes=False,
        )
    )

    assert result.total == 1
    assert not result.candidates[0].breaking_change


def test_duplicate_candidates_are_removed():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate("1.1.0", 20, index=0),
                candidate("1.1.0", 20, index=1),
            ]
        )
    )

    assert result.total == 1


def test_duplicate_keeps_higher_risk_signal():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate("1.1.0", 20, index=0),
                candidate("1.1.0", 40, index=1),
            ]
        )
    )

    assert result.total == 1
    assert result.candidates[0].risk_score == 40


def test_compatibility_breaks_risk_tie():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "1.1.0",
                    30,
                    compatibility=70,
                    index=0,
                ),
                candidate(
                    "1.2.0",
                    30,
                    compatibility=90,
                    index=1,
                ),
            ]
        )
    )

    assert (
        result.candidates[0].candidate_version
        == "1.2.0"
    )


def test_security_breaks_risk_tie():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "1.1.0",
                    30,
                    security=60,
                    index=0,
                ),
                candidate(
                    "1.2.0",
                    30,
                    security=90,
                    index=1,
                ),
            ]
        )
    )

    assert (
        result.candidates[0].candidate_version
        == "1.2.0"
    )


def test_confidence_breaks_risk_tie():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "1.1.0",
                    30,
                    confidence=60,
                    index=0,
                ),
                candidate(
                    "1.2.0",
                    30,
                    confidence=90,
                    index=1,
                ),
            ]
        )
    )

    assert (
        result.candidates[0].candidate_version
        == "1.2.0"
    )


def test_non_breaking_beats_breaking():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "2.0.0",
                    30,
                    breaking=True,
                    index=0,
                ),
                candidate(
                    "1.1.0",
                    30,
                    breaking=False,
                    index=1,
                ),
            ]
        )
    )

    assert (
        result.candidates[0].candidate_version
        == "1.1.0"
    )


def test_upgrade_distance_breaks_tie():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "1.5.0",
                    30,
                    distance=20,
                    index=0,
                ),
                candidate(
                    "1.1.1",
                    30,
                    distance=2,
                    index=1,
                ),
            ]
        )
    )

    assert (
        result.candidates[0].candidate_version
        == "1.1.1"
    )


def test_original_index_is_final_tie_breaker():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "1.1.0",
                    30,
                    index=5,
                ),
                candidate(
                    "1.2.0",
                    30,
                    index=2,
                ),
            ]
        )
    )

    assert [
        item.original_index
        for item in result.candidates
    ] == [2, 5]


def test_empty_input():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[]
        )
    )

    assert result.candidates == ()
    assert result.total == 0
    assert result.selected_count == 0
    assert result.excluded_count == 0


def test_zero_max_candidates():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate()
            ],
            max_candidates=0,
        )
    )

    assert result.candidates == ()
    assert result.total == 0
    assert result.excluded_count == 1


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        build_remediation_candidate_set(None)


def test_none_candidates_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATES_IS_NONE",
    ):
        build_remediation_candidate_set(
            RemediationCandidateSetInput(
                candidates=None
            )
        )


def test_string_candidates_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATES_MUST_BE_SEQUENCE",
    ):
        build_remediation_candidate_set(
            RemediationCandidateSetInput(
                candidates="invalid"
            )
        )


def test_unsupported_candidate_type():
    with pytest.raises(
        TypeError,
        match="UNSUPPORTED_CANDIDATE_TYPE",
    ):
        build_remediation_candidate_set(
            RemediationCandidateSetInput(
                candidates=[123]
            )
        )


def test_invalid_risk_score():
    item = candidate("1.1.0", 20)

    invalid = RemediationCandidate(
        **{
            **item.__dict__,
            "risk_score": 101,
        }
    )

    with pytest.raises(
        ValueError,
        match="RISK_SCORE_OUT_OF_RANGE",
    ):
        build_remediation_candidate_set(
            RemediationCandidateSetInput(
                candidates=[invalid]
            )
        )


def test_invalid_risk_level():
    item = candidate("1.1.0", 20)

    invalid = RemediationCandidate(
        **{
            **item.__dict__,
            "risk_level": "UNKNOWN",
        }
    )

    with pytest.raises(
        ValueError,
        match="INVALID_RISK_LEVEL",
    ):
        build_remediation_candidate_set(
            RemediationCandidateSetInput(
                candidates=[invalid]
            )
        )


def test_mapping_candidate():
    item = candidate("1.1.0", 20)

    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[item.__dict__]
        )
    )

    assert result.total == 1


def test_mapping_invalid():
    with pytest.raises(
        TypeError,
        match="INVALID_CANDIDATE_MAPPING",
    ):
        build_remediation_candidate_set(
            RemediationCandidateSetInput(
                candidates=[
                    {"package_name": "demo"}
                ]
            )
        )


def test_result_contains_original_metadata():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "1.2.0",
                    30,
                    index=7,
                )
            ]
        )
    )

    item = result.candidates[0]

    assert item.package_name == "demo"
    assert item.current_version == "1.0.0"
    assert item.candidate_version == "1.2.0"
    assert item.original_index == 7


def test_aliases():
    assert (
        remediation_candidate_set
        is build_remediation_candidate_set
    )
    assert (
        create_remediation_candidate_set
        is build_remediation_candidate_set
    )


def test_deterministic_result():
    items = [
        candidate("1.1.0", 20, index=0),
        candidate("1.2.0", 40, index=1),
    ]

    assert (
        build_remediation_candidate_set(
            RemediationCandidateSetInput(items)
        )
        == build_remediation_candidate_set(
            RemediationCandidateSetInput(items)
        )
    )


def test_input_is_not_modified():
    items = [
        candidate("1.1.0", 20, index=0),
        candidate("1.2.0", 40, index=1),
    ]

    original = list(items)

    build_remediation_candidate_set(
        RemediationCandidateSetInput(items)
    )

    assert items == original


def test_combined_filters():
    result = build_remediation_candidate_set(
        RemediationCandidateSetInput(
            candidates=[
                candidate(
                    "1.1.0",
                    10,
                    index=0,
                ),
                candidate(
                    "1.2.0",
                    30,
                    index=1,
                ),
                candidate(
                    "2.0.0",
                    40,
                    breaking=True,
                    index=2,
                ),
                candidate(
                    "3.0.0",
                    80,
                    breaking=True,
                    index=3,
                ),
            ],
            max_candidates=2,
            max_risk_score=50,
            include_breaking_changes=False,
        )
    )

    assert result.total == 2
    assert [
        item.risk_score
        for item in result.candidates
    ] == [10.0, 30.0]
