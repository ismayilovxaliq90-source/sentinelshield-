import pytest

from sentinelshield.candidate_risk_scoring import (
    CandidateRiskInput,
    CandidateRiskScore,
    CandidateRiskScoringResult,
    calculate_candidate_risk,
    candidate_risk_scoring,
    score_candidate_risk,
)


def test_low_risk_candidate():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="1.0.1",
                breaking_change=False,
                patch_upgrade=True,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
                upgrade_distance=0,
            )
        ]
    )

    assert result.scores[0].risk_score == 0.0
    assert result.scores[0].risk_level == "LOW"


def test_breaking_change_increases_risk():
    safe = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="1.0.1",
                patch_upgrade=True,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    breaking = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="2.0.0",
                breaking_change=True,
                major_upgrade=True,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    assert (
        breaking.scores[0].risk_score
        > safe.scores[0].risk_score
    )


def test_major_upgrade_adds_risk():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="2.0.0",
                major_upgrade=True,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    assert result.scores[0].risk_score == 5.0
    assert result.scores[0].risk_level == "LOW"


def test_minor_upgrade_adds_less_risk_than_major():
    major = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="2.0.0",
                major_upgrade=True,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    minor = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="1.1.0",
                minor_upgrade=True,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    assert (
        major.scores[0].risk_score
        > minor.scores[0].risk_score
    )


def test_upgrade_distance_contributes_to_risk():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="1.5.0",
                upgrade_distance=20,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    assert result.scores[0].risk_score == 4.0


def test_security_score_deficit_contributes():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="1.0.1",
                security_score=50,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    assert result.scores[0].risk_score == 10.0


def test_compatibility_deficit_contributes():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="1.0.1",
                security_score=100,
                compatibility_score=50,
                confidence_score=100,
            )
        ]
    )

    assert result.scores[0].risk_score == 7.5


def test_confidence_deficit_contributes():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="1.0.1",
                security_score=100,
                compatibility_score=100,
                confidence_score=50,
            )
        ]
    )

    assert result.scores[0].risk_score == 5.0


def test_full_risk_score_is_clamped_to_100():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="demo",
                current_version="1.0.0",
                candidate_version="10.0.0",
                breaking_change=True,
                major_upgrade=True,
                security_score=0,
                compatibility_score=0,
                confidence_score=0,
                upgrade_distance=1000,
            )
        ]
    )

    assert result.scores[0].risk_score == 100.0
    assert result.scores[0].risk_level == "CRITICAL"


def test_risk_levels():
    low = score_candidate_risk(
        [
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "1.0.1",
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    high = score_candidate_risk(
        [
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "2.0.0",
                breaking_change=True,
                major_upgrade=True,
                security_score=0,
                compatibility_score=100,
                confidence_score=100,
            )
        ]
    )

    assert low.scores[0].risk_level == "LOW"
    assert high.scores[0].risk_level == "HIGH"


def test_multiple_candidates_are_sorted_by_risk():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "1.0.1",
                patch_upgrade=True,
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
                original_index=0,
            ),
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "2.0.0",
                breaking_change=True,
                major_upgrade=True,
                security_score=0,
                compatibility_score=0,
                confidence_score=0,
                upgrade_distance=100,
                original_index=1,
            ),
        ]
    )

    assert (
        result.scores[0].candidate_version
        == "2.0.0"
    )


def test_tie_uses_original_index():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "1.0.1",
                security_score=90,
                original_index=5,
            ),
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "1.0.2",
                security_score=90,
                original_index=2,
            ),
        ]
    )

    assert [
        item.original_index
        for item in result.scores
    ] == [2, 5]


def test_missing_scores_default_to_zero():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "1.0.1",
            )
        ]
    )

    assert result.scores[0].security_score == 0.0
    assert result.scores[0].compatibility_score == 0.0
    assert result.scores[0].confidence_score == 0.0


def test_mapping_input_is_supported():
    result = score_candidate_risk(
        [
            {
                "package_name": "demo",
                "current_version": "1.0.0",
                "candidate_version": "1.0.1",
                "security_score": 100,
                "compatibility_score": 100,
                "confidence_score": 100,
            }
        ]
    )

    assert result.total == 1


def test_none_candidates_rejected():
    with pytest.raises(TypeError, match="CANDIDATES_IS_NONE"):
        score_candidate_risk(None)


def test_string_candidates_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATES_MUST_BE_SEQUENCE",
    ):
        score_candidate_risk("invalid")


def test_unsupported_candidate_rejected():
    with pytest.raises(
        TypeError,
        match="UNSUPPORTED_CANDIDATE_TYPE:0",
    ):
        score_candidate_risk([123])


def test_invalid_bool_rejected():
    with pytest.raises(
        TypeError,
        match="BREAKING_CHANGE_MUST_BE_BOOL",
    ):
        score_candidate_risk(
            [
                CandidateRiskInput(
                    "demo",
                    "1.0.0",
                    "2.0.0",
                    breaking_change=1,
                )
            ]
        )


def test_invalid_score_rejected():
    with pytest.raises(
        ValueError,
        match="SECURITY_SCORE_OUT_OF_RANGE",
    ):
        score_candidate_risk(
            [
                CandidateRiskInput(
                    "demo",
                    "1.0.0",
                    "1.0.1",
                    security_score=101,
                )
            ]
        )


def test_invalid_distance_rejected():
    with pytest.raises(
        ValueError,
        match="UPGRADE_DISTANCE_MUST_BE_NON_NEGATIVE",
    ):
        score_candidate_risk(
            [
                CandidateRiskInput(
                    "demo",
                    "1.0.0",
                    "1.0.1",
                    upgrade_distance=-1,
                )
            ]
        )


def test_metadata_and_reasons():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                package_name="requests",
                current_version="2.31.0",
                candidate_version="3.0.0",
                breaking_change=True,
                major_upgrade=True,
                security_score=20,
                compatibility_score=20,
                confidence_score=20,
                upgrade_distance=100,
            )
        ]
    )

    item = result.scores[0]

    assert item.package_name == "requests"
    assert item.current_version == "2.31.0"
    assert item.candidate_version == "3.0.0"
    assert "BREAKING_CHANGE" in item.reasons
    assert "MAJOR_UPGRADE" in item.reasons
    assert "LOW_SECURITY_SCORE" in item.reasons
    assert "LOW_COMPATIBILITY_SCORE" in item.reasons
    assert "LOW_CONFIDENCE_SCORE" in item.reasons
    assert "LARGE_UPGRADE_DISTANCE" in item.reasons


def test_result_counters():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "1.0.1",
                security_score=100,
                compatibility_score=100,
                confidence_score=100,
            ),
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "2.0.0",
                breaking_change=True,
                major_upgrade=True,
                security_score=0,
                compatibility_score=0,
                confidence_score=0,
                upgrade_distance=100,
            ),
        ]
    )

    assert result.total == 2
    assert result.high_risk_count == 1
    assert result.low_risk_count == 1


def test_dataclasses_and_aliases():
    result = score_candidate_risk(
        [
            CandidateRiskInput(
                "demo",
                "1.0.0",
                "1.0.1",
            )
        ]
    )

    assert isinstance(result, CandidateRiskScoringResult)
    assert isinstance(result.scores[0], CandidateRiskScore)

    assert candidate_risk_scoring is score_candidate_risk
    assert calculate_candidate_risk is score_candidate_risk


def test_deterministic_result():
    candidates = [
        CandidateRiskInput(
            "demo",
            "1.0.0",
            "1.1.0",
            minor_upgrade=True,
            security_score=70,
            compatibility_score=80,
            confidence_score=90,
            original_index=0,
        ),
        CandidateRiskInput(
            "demo",
            "1.0.0",
            "2.0.0",
            breaking_change=True,
            major_upgrade=True,
            security_score=60,
            compatibility_score=70,
            confidence_score=80,
            original_index=1,
        ),
    ]

    assert (
        score_candidate_risk(candidates)
        == score_candidate_risk(candidates)
    )


def test_input_is_not_modified():
    candidates = [
        CandidateRiskInput(
            "demo",
            "1.0.0",
            "1.1.0",
            original_index=0,
        )
    ]

    original = list(candidates)

    score_candidate_risk(candidates)

    assert candidates == original
