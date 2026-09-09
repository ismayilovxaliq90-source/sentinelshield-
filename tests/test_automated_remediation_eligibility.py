import pytest

from sentinelshield.automated_remediation_eligibility import (
    AutomatedRemediationEligibilityInput,
    AutomatedRemediationEligibilityResult,
    automated_remediation_eligibility,
    check_automated_remediation_eligibility,
    evaluate_automated_remediation_eligibility,
    is_automated_remediation_eligible,
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


def request(automated=False):
    return AutomatedRemediationEligibilityInput(
        policy=make_policy(
            automated_remediation=automated
        )
    )


def test_automated_remediation_enabled():
    result = evaluate_automated_remediation_eligibility(
        request(True)
    )

    assert isinstance(
        result,
        AutomatedRemediationEligibilityResult,
    )
    assert result.eligible is True
    assert result.automated_remediation is True
    assert result.reason == "AUTOMATED_REMEDIATION_ELIGIBLE"


def test_automated_remediation_disabled():
    result = evaluate_automated_remediation_eligibility(
        request(False)
    )

    assert result.eligible is False
    assert result.automated_remediation is False
    assert (
        result.reason
        == "AUTOMATED_REMEDIATION_NOT_ELIGIBLE"
    )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_automated_remediation_eligibility(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_AUTOMATED_REMEDIATION_ELIGIBILITY_INPUT",
    ):
        evaluate_automated_remediation_eligibility({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_automated_remediation_eligibility(
            AutomatedRemediationEligibilityInput(
                policy=None
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_automated_remediation_eligibility(
            AutomatedRemediationEligibilityInput(
                policy={}
            )
        )


def test_automated_policy_value_must_be_boolean():
    with pytest.raises(
        TypeError,
        match="AUTOMATED_REMEDIATION_MUST_BE_BOOLEAN",
    ):
        evaluate_automated_remediation_eligibility(
            AutomatedRemediationEligibilityInput(
                policy=make_policy(
                    automated_remediation=1
                )
            )
        )


def test_none_automated_policy_value_rejected():
    with pytest.raises(
        TypeError,
        match="AUTOMATED_REMEDIATION_MUST_BE_BOOLEAN",
    ):
        evaluate_automated_remediation_eligibility(
            AutomatedRemediationEligibilityInput(
                policy=make_policy(
                    automated_remediation=None
                )
            )
        )


def test_boolean_helper_when_enabled():
    assert (
        is_automated_remediation_eligible(
            request(True)
        )
        is True
    )


def test_boolean_helper_when_disabled():
    assert (
        is_automated_remediation_eligible(
            request(False)
        )
        is False
    )


def test_public_aliases_enabled():
    req = request(True)
    expected = evaluate_automated_remediation_eligibility(req)

    assert automated_remediation_eligibility(req) == expected
    assert (
        check_automated_remediation_eligibility(req)
        == expected
    )


def test_public_aliases_disabled():
    req = request(False)
    expected = evaluate_automated_remediation_eligibility(req)

    assert automated_remediation_eligibility(req) == expected
    assert (
        check_automated_remediation_eligibility(req)
        == expected
    )


def test_policy_is_not_mutated():
    policy = make_policy(
        automated_remediation=True
    )

    before = policy.automated_remediation

    evaluate_automated_remediation_eligibility(
        AutomatedRemediationEligibilityInput(
            policy=policy
        )
    )

    assert policy.automated_remediation == before


def test_deterministic_result():
    req = request(True)

    first = evaluate_automated_remediation_eligibility(req)
    second = evaluate_automated_remediation_eligibility(req)

    assert first == second


def test_enabled_and_disabled_are_distinct():
    enabled = evaluate_automated_remediation_eligibility(
        request(True)
    )
    disabled = evaluate_automated_remediation_eligibility(
        request(False)
    )

    assert enabled.eligible is True
    assert disabled.eligible is False
    assert (
        enabled.reason
        != disabled.reason
    )


def test_result_preserves_policy_value():
    enabled = evaluate_automated_remediation_eligibility(
        request(True)
    )
    disabled = evaluate_automated_remediation_eligibility(
        request(False)
    )

    assert enabled.automated_remediation is True
    assert disabled.automated_remediation is False
