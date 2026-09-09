import pytest

from sentinelshield.risk_threshold_gate import (
    RiskThresholdGateInput,
    RiskThresholdGateResult,
    check_risk_threshold,
    evaluate_risk_threshold_gate,
    is_risk_threshold_allowed,
    risk_threshold_gate,
)

from sentinelshield.remediation_policy_loading import (
    RemediationPolicy,
)


def make_policy(**overrides):
    values = {
        "policy_name": "security",
        "version": "1",
        "allowed_versions": (),
        "forbidden_versions": (),
        "maximum_upgrade_distance": None,
        "allow_major_upgrades": False,
        "allow_production_dependencies": True,
        "allow_development_dependencies": True,
        "automated_remediation": False,
        "manual_approval_required": True,
        "risk_threshold": 50.0,
        "change_scope": "DEPENDENCY",
        "dependency_policy": "STRICT",
    }

    values.update(overrides)
    return RemediationPolicy(**values)


def request(
    risk_score=50.0,
    risk_threshold=50.0,
):
    return RiskThresholdGateInput(
        policy=make_policy(
            risk_threshold=risk_threshold
        ),
        risk_score=risk_score,
    )


def test_risk_score_below_threshold_is_allowed():
    result = evaluate_risk_threshold_gate(
        request(
            risk_score=49.99,
            risk_threshold=50.0,
        )
    )

    assert isinstance(
        result,
        RiskThresholdGateResult,
    )
    assert result.allowed is True
    assert result.risk_score == 49.99
    assert result.risk_threshold == 50.0
    assert (
        result.reason
        == "RISK_SCORE_WITHIN_THRESHOLD"
    )


def test_risk_score_equal_to_threshold_is_allowed():
    result = evaluate_risk_threshold_gate(
        request(
            risk_score=50.0,
            risk_threshold=50.0,
        )
    )

    assert result.allowed is True
    assert result.reason == "RISK_SCORE_WITHIN_THRESHOLD"


def test_risk_score_above_threshold_is_rejected():
    result = evaluate_risk_threshold_gate(
        request(
            risk_score=50.01,
            risk_threshold=50.0,
        )
    )

    assert result.allowed is False
    assert result.risk_score == 50.01
    assert result.risk_threshold == 50.0
    assert (
        result.reason
        == "RISK_SCORE_EXCEEDS_THRESHOLD"
    )


def test_zero_threshold():
    assert (
        evaluate_risk_threshold_gate(
            request(
                risk_score=0.0,
                risk_threshold=0.0,
            )
        ).allowed
        is True
    )

    assert (
        evaluate_risk_threshold_gate(
            request(
                risk_score=0.01,
                risk_threshold=0.0,
            )
        ).allowed
        is False
    )


def test_maximum_threshold():
    result = evaluate_risk_threshold_gate(
        request(
            risk_score=100.0,
            risk_threshold=100.0,
        )
    )

    assert result.allowed is True


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_risk_threshold_gate(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_RISK_THRESHOLD_GATE_INPUT",
    ):
        evaluate_risk_threshold_gate({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_risk_threshold_gate(
            RiskThresholdGateInput(
                policy=None,
                risk_score=50.0,
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_risk_threshold_gate(
            RiskThresholdGateInput(
                policy={},
                risk_score=50.0,
            )
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        "50",
        [],
        {},
        True,
        False,
    ],
)
def test_invalid_risk_score_type_rejected(value):
    with pytest.raises(
        TypeError,
        match="RISK_SCORE_MUST_BE_NUMERIC",
    ):
        evaluate_risk_threshold_gate(
            request(
                risk_score=value,
                risk_threshold=50.0,
            )
        )


@pytest.mark.parametrize(
    "value",
    [-0.01, 100.01],
)
def test_risk_score_range_rejected(value):
    with pytest.raises(
        ValueError,
        match="RISK_SCORE_MUST_BE_BETWEEN_0_AND_100",
    ):
        evaluate_risk_threshold_gate(
            request(
                risk_score=value,
                risk_threshold=50.0,
            )
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        "50",
        [],
        {},
        True,
        False,
    ],
)
def test_invalid_risk_threshold_type_rejected(value):
    with pytest.raises(
        TypeError,
        match="RISK_THRESHOLD_MUST_BE_NUMERIC",
    ):
        evaluate_risk_threshold_gate(
            request(
                risk_score=50.0,
                risk_threshold=value,
            )
        )


@pytest.mark.parametrize(
    "value",
    [-0.01, 100.01],
)
def test_risk_threshold_range_rejected(value):
    with pytest.raises(
        ValueError,
        match="RISK_THRESHOLD_MUST_BE_BETWEEN_0_AND_100",
    ):
        evaluate_risk_threshold_gate(
            request(
                risk_score=50.0,
                risk_threshold=value,
            )
        )


def test_integer_scores_are_supported():
    result = evaluate_risk_threshold_gate(
        request(
            risk_score=25,
            risk_threshold=50,
        )
    )

    assert result.allowed is True
    assert result.risk_score == 25.0
    assert result.risk_threshold == 50.0


def test_float_scores_are_supported():
    result = evaluate_risk_threshold_gate(
        request(
            risk_score=25.75,
            risk_threshold=50.25,
        )
    )

    assert result.allowed is True
    assert result.risk_score == 25.75
    assert result.risk_threshold == 50.25


def test_policy_is_not_mutated():
    policy = make_policy(
        risk_threshold=60.0
    )

    before = policy.risk_threshold

    evaluate_risk_threshold_gate(
        RiskThresholdGateInput(
            policy=policy,
            risk_score=40.0,
        )
    )

    assert policy.risk_threshold == before


def test_boolean_helper_allowed():
    assert (
        is_risk_threshold_allowed(
            request(
                risk_score=40.0,
                risk_threshold=50.0,
            )
        )
        is True
    )


def test_boolean_helper_rejected():
    assert (
        is_risk_threshold_allowed(
            request(
                risk_score=60.0,
                risk_threshold=50.0,
            )
        )
        is False
    )


def test_public_aliases_allowed():
    req = request(
        risk_score=40.0,
        risk_threshold=50.0,
    )

    expected = evaluate_risk_threshold_gate(req)

    assert risk_threshold_gate(req) == expected
    assert check_risk_threshold(req) == expected


def test_public_aliases_rejected():
    req = request(
        risk_score=60.0,
        risk_threshold=50.0,
    )

    expected = evaluate_risk_threshold_gate(req)

    assert risk_threshold_gate(req) == expected
    assert check_risk_threshold(req) == expected


def test_deterministic_result():
    req = request(
        risk_score=60.0,
        risk_threshold=50.0,
    )

    first = evaluate_risk_threshold_gate(req)
    second = evaluate_risk_threshold_gate(req)

    assert first == second


def test_result_contains_exact_inputs():
    result = evaluate_risk_threshold_gate(
        request(
            risk_score=73.25,
            risk_threshold=74.0,
        )
    )

    assert result.risk_score == 73.25
    assert result.risk_threshold == 74.0


def test_threshold_gate_is_independent_of_other_policy_flags():
    policy = make_policy(
        risk_threshold=50.0,
        automated_remediation=True,
        manual_approval_required=False,
        allow_major_upgrades=True,
        allow_production_dependencies=False,
        allow_development_dependencies=False,
    )

    result = evaluate_risk_threshold_gate(
        RiskThresholdGateInput(
            policy=policy,
            risk_score=50.0,
        )
    )

    assert result.allowed is True
    assert result.reason == "RISK_SCORE_WITHIN_THRESHOLD"
