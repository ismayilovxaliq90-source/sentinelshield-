import pytest

from sentinelshield.candidate_ranking import (
    CandidateRankingInput,
    CandidateRankingResult,
    RankedCandidate,
    candidate_ranking,
    rank_candidates,
    rank_remediation_candidates,
)


def make_candidate(
    version,
    risk,
    *,
    compatibility=100,
    security=100,
    confidence=100,
    breaking=False,
    distance=0,
    index=0,
):
    return CandidateRankingInput(
        package_name="demo",
        current_version="1.0.0",
        candidate_version=version,
        risk_score=risk,
        compatibility_score=compatibility,
        security_score=security,
        confidence_score=confidence,
        breaking_change=breaking,
        upgrade_distance=distance,
        original_index=index,
    )


def test_lowest_risk_is_rank_one():
    result = rank_candidates(
        [
            make_candidate("2.0.0", 70, index=0),
            make_candidate("1.1.0", 20, index=1),
        ]
    )

    assert result.candidates[0].candidate_version == "1.1.0"
    assert result.candidates[0].rank == 1


def test_candidates_are_ranked_ascending_by_risk():
    result = rank_candidates(
        [
            make_candidate("1.3.0", 60, index=0),
            make_candidate("1.1.0", 10, index=1),
            make_candidate("1.2.0", 40, index=2),
        ]
    )

    assert [
        item.risk_score
        for item in result.candidates
    ] == [10.0, 40.0, 60.0]


def test_compatibility_breaks_risk_tie():
    result = rank_candidates(
        [
            make_candidate(
                "1.1.0",
                30,
                compatibility=60,
                index=0,
            ),
            make_candidate(
                "1.2.0",
                30,
                compatibility=90,
                index=1,
            ),
        ]
    )

    assert result.candidates[0].candidate_version == "1.2.0"


def test_security_breaks_tie():
    result = rank_candidates(
        [
            make_candidate(
                "1.1.0",
                30,
                compatibility=90,
                security=50,
                index=0,
            ),
            make_candidate(
                "1.2.0",
                30,
                compatibility=90,
                security=90,
                index=1,
            ),
        ]
    )

    assert result.candidates[0].candidate_version == "1.2.0"


def test_confidence_breaks_tie():
    result = rank_candidates(
        [
            make_candidate(
                "1.1.0",
                30,
                compatibility=90,
                security=90,
                confidence=50,
                index=0,
            ),
            make_candidate(
                "1.2.0",
                30,
                compatibility=90,
                security=90,
                confidence=90,
                index=1,
            ),
        ]
    )

    assert result.candidates[0].candidate_version == "1.2.0"


def test_non_breaking_beats_breaking_on_complete_tie():
    result = rank_candidates(
        [
            make_candidate(
                "2.0.0",
                30,
                breaking=True,
                index=0,
            ),
            make_candidate(
                "1.1.0",
                30,
                breaking=False,
                index=1,
            ),
        ]
    )

    assert result.candidates[0].candidate_version == "1.1.0"


def test_smaller_upgrade_distance_breaks_tie():
    result = rank_candidates(
        [
            make_candidate(
                "1.5.0",
                30,
                distance=50,
                index=0,
            ),
            make_candidate(
                "1.1.1",
                30,
                distance=5,
                index=1,
            ),
        ]
    )

    assert result.candidates[0].candidate_version == "1.1.1"


def test_original_index_is_final_tie_breaker():
    result = rank_candidates(
        [
            make_candidate("1.1.0", 30, index=5),
            make_candidate("1.2.0", 30, index=2),
        ]
    )

    assert [
        item.original_index
        for item in result.candidates
    ] == [2, 5]


def test_rank_numbers_are_sequential():
    result = rank_candidates(
        [
            make_candidate("1.1.0", 30, index=0),
            make_candidate("1.2.0", 20, index=1),
            make_candidate("1.3.0", 10, index=2),
        ]
    )

    assert [
        item.rank
        for item in result.candidates
    ] == [1, 2, 3]


def test_risk_levels_are_derived():
    result = rank_candidates(
        [
            make_candidate("1.1.0", 10, index=0),
            make_candidate("1.2.0", 30, index=1),
            make_candidate("1.3.0", 60, index=2),
            make_candidate("1.4.0", 80, index=3),
        ]
    )

    assert [
        item.risk_level
        for item in result.candidates
    ] == [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]


def test_empty_input():
    result = rank_candidates([])

    assert isinstance(result, CandidateRankingResult)
    assert result.total == 0
    assert result.candidates == ()


def test_mapping_input():
    result = rank_candidates(
        [
            {
                "package_name": "demo",
                "current_version": "1.0.0",
                "candidate_version": "1.1.0",
                "risk_score": 20,
            }
        ]
    )

    assert result.total == 1
    assert result.candidates[0].candidate_version == "1.1.0"


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATES_IS_NONE",
    ):
        rank_candidates(None)


def test_string_input_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATES_MUST_BE_SEQUENCE",
    ):
        rank_candidates("invalid")


def test_unsupported_item_rejected():
    with pytest.raises(
        TypeError,
        match="UNSUPPORTED_CANDIDATE_TYPE:0",
    ):
        rank_candidates([123])


def test_invalid_risk_score_rejected():
    with pytest.raises(
        ValueError,
        match="RISK_SCORE_OUT_OF_RANGE",
    ):
        rank_candidates(
            [
                make_candidate("1.1.0", 101)
            ]
        )


def test_invalid_risk_level_rejected():
    item = CandidateRankingInput(
        "demo",
        "1.0.0",
        "1.1.0",
        risk_score=20,
        risk_level="UNKNOWN",
    )

    with pytest.raises(
        ValueError,
        match="INVALID_RISK_LEVEL",
    ):
        rank_candidates([item])


def test_risk_level_mismatch_rejected():
    item = CandidateRankingInput(
        "demo",
        "1.0.0",
        "1.1.0",
        risk_score=20,
        risk_level="HIGH",
    )

    with pytest.raises(
        ValueError,
        match="RISK_LEVEL_MISMATCH",
    ):
        rank_candidates([item])


def test_invalid_bool_rejected():
    item = CandidateRankingInput(
        "demo",
        "1.0.0",
        "2.0.0",
        risk_score=20,
        breaking_change=1,
    )

    with pytest.raises(
        TypeError,
        match="BREAKING_CHANGE_MUST_BE_BOOL",
    ):
        rank_candidates([item])


def test_invalid_package_name_rejected():
    item = CandidateRankingInput(
        "",
        "1.0.0",
        "1.1.0",
        risk_score=20,
    )

    with pytest.raises(
        ValueError,
        match="PACKAGE_NAME_IS_EMPTY",
    ):
        rank_candidates([item])


def test_invalid_distance_rejected():
    item = CandidateRankingInput(
        "demo",
        "1.0.0",
        "1.1.0",
        risk_score=20,
        upgrade_distance=-1,
    )

    with pytest.raises(
        ValueError,
        match="UPGRADE_DISTANCE_MUST_BE_NON_NEGATIVE",
    ):
        rank_candidates([item])


def test_result_metadata():
    result = rank_candidates(
        [
            CandidateRankingInput(
                package_name="requests",
                current_version="2.31.0",
                candidate_version="2.32.0",
                risk_score=35,
                compatibility_score=90,
                security_score=80,
                confidence_score=95,
                minor_upgrade=True,
                original_index=7,
            )
        ]
    )

    item = result.candidates[0]

    assert item.rank == 1
    assert item.package_name == "requests"
    assert item.current_version == "2.31.0"
    assert item.candidate_version == "2.32.0"
    assert item.risk_score == 35.0
    assert item.risk_level == "MEDIUM"
    assert item.original_index == 7


def test_dataclass_types():
    result = rank_candidates(
        [
            make_candidate("1.1.0", 20)
        ]
    )

    assert isinstance(result, CandidateRankingResult)
    assert isinstance(result.candidates[0], RankedCandidate)


def test_aliases():
    assert candidate_ranking is rank_candidates
    assert rank_remediation_candidates is rank_candidates


def test_deterministic_result():
    candidates = [
        make_candidate(
            "1.1.0",
            25,
            compatibility=80,
            security=80,
            confidence=80,
            index=0,
        ),
        make_candidate(
            "1.2.0",
            50,
            compatibility=90,
            security=90,
            confidence=90,
            index=1,
        ),
    ]

    assert rank_candidates(candidates) == rank_candidates(candidates)


def test_input_is_not_modified():
    candidates = [
        make_candidate("1.1.0", 20, index=0),
        make_candidate("1.2.0", 50, index=1),
    ]

    original = list(candidates)

    rank_candidates(candidates)

    assert candidates == original


def test_ranking_preserves_all_candidates():
    candidates = [
        make_candidate("1.1.0", 20, index=0),
        make_candidate("1.2.0", 40, index=1),
        make_candidate("2.0.0", 80, index=2),
    ]

    result = rank_candidates(candidates)

    assert result.total == len(candidates)
    assert {
        item.candidate_version
        for item in result.candidates
    } == {
        "1.1.0",
        "1.2.0",
        "2.0.0",
    }
