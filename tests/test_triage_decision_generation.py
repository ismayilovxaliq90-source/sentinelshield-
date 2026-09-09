import math

import pytest

from sentinelshield.triage_decision_generation import (
    AnalystPriority,
    TriageAction,
    TriageDecisionInput,
    TriageRiskLevel,
    generate_triage_decision,
    triage_decision_generation,
)


def test_empty_input_defaults_to_low_monitoring():
    result = generate_triage_decision(TriageDecisionInput())

    assert result.decision.score == 0.0
    assert result.decision.risk_level is TriageRiskLevel.LOW
    assert result.decision.recommended_action is TriageAction.MONITOR
    assert result.decision.analyst_priority is AnalystPriority.LOW
    assert "NO_TRIAGE_SIGNAL_AVAILABLE" in result.decision.explanation


def test_low_triage():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 10,
            "authentication_anomaly_score": 20,
            "process_behavior_risk_score": 15,
            "malware_file_reputation_score": 5,
        }
    )

    assert result.decision.score == 12.5
    assert result.decision.risk_level is TriageRiskLevel.LOW
    assert result.decision.recommended_action is TriageAction.MONITOR


def test_medium_triage():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 30,
            "authentication_anomaly_score": 40,
            "process_behavior_risk_score": 35,
            "malware_file_reputation_score": 35,
        }
    )

    assert result.decision.score == 35.0
    assert result.decision.risk_level is TriageRiskLevel.MEDIUM
    assert result.decision.recommended_action is TriageAction.REVIEW
    assert result.decision.analyst_priority is AnalystPriority.MEDIUM


def test_high_triage():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 60,
            "authentication_anomaly_score": 55,
            "process_behavior_risk_score": 65,
            "malware_file_reputation_score": 60,
        }
    )

    assert result.decision.score == 60.0
    assert result.decision.risk_level is TriageRiskLevel.HIGH
    assert result.decision.recommended_action is TriageAction.INVESTIGATE
    assert result.decision.analyst_priority is AnalystPriority.HIGH


def test_critical_triage():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 90,
            "authentication_anomaly_score": 85,
            "process_behavior_risk_score": 95,
            "malware_file_reputation_score": 90,
        }
    )

    assert result.decision.score == 90.0
    assert result.decision.risk_level is TriageRiskLevel.CRITICAL
    assert (
        result.decision.recommended_action
        is TriageAction.IMMEDIATE_RESPONSE
    )
    assert result.decision.analyst_priority is AnalystPriority.CRITICAL


def test_partial_input_uses_available_signals_only():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 80,
            "authentication_anomaly_score": None,
            "process_behavior_risk_score": None,
            "malware_file_reputation_score": 60,
        }
    )

    assert result.decision.score == 70.0
    assert result.decision.risk_level is TriageRiskLevel.HIGH


def test_dataclass_input():
    data = TriageDecisionInput(
        endpoint_signal_score=70,
        authentication_anomaly_score=70,
        process_behavior_risk_score=70,
        malware_file_reputation_score=70,
    )

    result = generate_triage_decision(data)

    assert result.decision.score == 70.0
    assert result.decision.risk_level is TriageRiskLevel.HIGH


def test_mapping_input_is_supported():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 75,
            "authentication_anomaly_score": 75,
        }
    )

    assert result.decision.score == 75.0
    assert result.decision.risk_level is TriageRiskLevel.CRITICAL


def test_boundary_25_is_medium():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 25,
        }
    )

    assert result.decision.score == 25.0
    assert result.decision.risk_level is TriageRiskLevel.MEDIUM


def test_boundary_50_is_high():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 50,
        }
    )

    assert result.decision.score == 50.0
    assert result.decision.risk_level is TriageRiskLevel.HIGH


def test_boundary_75_is_critical():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 75,
        }
    )

    assert result.decision.score == 75.0
    assert result.decision.risk_level is TriageRiskLevel.CRITICAL


def test_score_is_clamped_and_rounded():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 33.333,
        }
    )

    assert result.decision.score == 33.33


def test_boolean_score_is_rejected():
    with pytest.raises(TypeError):
        generate_triage_decision(
            {"endpoint_signal_score": True}
        )


def test_negative_score_is_rejected():
    with pytest.raises(ValueError):
        generate_triage_decision(
            {"endpoint_signal_score": -1}
        )


def test_score_above_100_is_rejected():
    with pytest.raises(ValueError):
        generate_triage_decision(
            {"endpoint_signal_score": 101}
        )


def test_nan_is_rejected():
    with pytest.raises(ValueError):
        generate_triage_decision(
            {"endpoint_signal_score": math.nan}
        )


def test_unknown_mapping_field_is_rejected():
    with pytest.raises(TypeError):
        generate_triage_decision(
            {
                "endpoint_signal_score": 50,
                "unexpected": 10,
            }
        )


def test_none_top_level_is_rejected():
    with pytest.raises(TypeError):
        generate_triage_decision(None)


def test_unsupported_top_level_type_is_rejected():
    with pytest.raises(TypeError):
        generate_triage_decision("invalid")


def test_input_mapping_is_not_mutated():
    source = {
        "endpoint_signal_score": 80,
        "authentication_anomaly_score": 40,
    }
    original = source.copy()

    generate_triage_decision(source)

    assert source == original


def test_deterministic_result():
    data = {
        "endpoint_signal_score": 88,
        "authentication_anomaly_score": 72,
        "process_behavior_risk_score": 91,
        "malware_file_reputation_score": 84,
    }

    first = generate_triage_decision(data)
    second = generate_triage_decision(data)

    assert first == second


def test_explanation_contains_decision_information():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 90,
            "authentication_anomaly_score": 90,
        }
    )

    explanation = result.decision.explanation

    assert "HIGH_ENDPOINT_SIGNAL_SCORE" in explanation
    assert "HIGH_AUTHENTICATION_ANOMALY_SCORE" in explanation
    assert "TRIAGE_RISK_LEVEL_CRITICAL" in explanation
    assert (
        "RECOMMENDED_ACTION_IMMEDIATE_RESPONSE"
        in explanation
    )
    assert "TRIAGE_SCORE_90.00" in explanation


def test_evidence_contains_available_upstream_signals():
    result = generate_triage_decision(
        {
            "endpoint_signal_score": 80,
            "authentication_anomaly_score": None,
            "process_behavior_risk_score": 60,
            "malware_file_reputation_score": None,
        }
    )

    assert result.decision.evidence == (
        "endpoint_signal_score=80.00",
        "process_behavior_risk_score=60.00",
    )


def test_public_alias():
    data = {
        "endpoint_signal_score": 80,
        "authentication_anomaly_score": 80,
    }

    assert triage_decision_generation(data) == generate_triage_decision(data)


def test_result_metadata():
    result = generate_triage_decision(
        {"endpoint_signal_score": 100}
    )

    assert result.decision.score == 100.0
    assert isinstance(result.decision.explanation, tuple)
    assert isinstance(result.decision.evidence, tuple)
