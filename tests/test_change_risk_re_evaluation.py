import pytest

from sentinelshield.change_risk_re_evaluation import (
    ChangeRiskReEvaluationInput,
    re_evaluate_change_risk,
)


def test_risk_increases_with_blast_radius():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=10,
            blast_radius={"app", "service"},
            changed_files={"src/a.py"},
        )
    )

    assert result.score > 10
    assert result.status == "INCREASED"


def test_critical_files_have_higher_weight():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=10,
            blast_radius=set(),
            changed_files=set(),
            critical_files={"pyproject.toml"},
        )
    )

    assert result.score == 20
    assert result.critical_file_count == 1


def test_sensitive_files_increase_risk():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=10,
            blast_radius=set(),
            changed_files=set(),
            security_sensitive_files={"config.yaml"},
        )
    )

    assert result.score == 20
    assert result.status == "INCREASED"


def test_score_is_capped_at_100():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=90,
            blast_radius={str(i) for i in range(20)},
            changed_files={str(i) for i in range(20)},
            critical_files={"a", "b", "c"},
            security_sensitive_files={"x", "y", "z"},
        )
    )

    assert result.score == 100


def test_unchanged_risk():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=25,
            blast_radius=set(),
            changed_files=set(),
        )
    )

    assert result.score == 25
    assert result.status == "UNCHANGED"
    assert result.unchanged is True


def test_risk_level_low():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=0,
            blast_radius={"a"},
            changed_files=set(),
        )
    )

    assert result.level == "LOW"


def test_risk_level_medium():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=25,
            blast_radius={"a"},
            changed_files=set(),
        )
    )

    assert result.level == "MEDIUM"


def test_risk_level_high():
    result = re_evaluate_change_risk(
        ChangeRiskReEvaluationInput(
            previous_score=55,
            blast_radius={"a"},
            changed_files=set(),
        )
    )

    assert result.level == "HIGH"


def test_invalid_score_is_rejected():
    with pytest.raises(
        ValueError,
        match="PREVIOUS_SCORE_OUT_OF_RANGE",
    ):
        re_evaluate_change_risk(
            ChangeRiskReEvaluationInput(
                previous_score=101,
                blast_radius=set(),
                changed_files=set(),
            )
        )


def test_invalid_input_is_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_CHANGE_RISK_RE_EVALUATION_INPUT",
    ):
        re_evaluate_change_risk(None)
