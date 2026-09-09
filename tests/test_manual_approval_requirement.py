import pytest

from sentinelshield.manual_approval_requirement import (
    ManualApprovalRequirementInput,
    ManualApprovalRequirementResult,
    check_manual_approval_requirement,
    evaluate_manual_approval_requirement,
    is_manual_approval_required,
    manual_approval_requirement,
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


def request(required=True):
    return ManualApprovalRequirementInput(
        policy=make_policy(
            manual_approval_required=required
        )
    )


def test_manual_approval_required():
    result = evaluate_manual_approval_requirement(
        request(True)
    )

    assert isinstance(
        result,
        ManualApprovalRequirementResult,
    )
    assert result.approval_required is True
    assert result.manual_approval_required is True
    assert result.reason == "MANUAL_APPROVAL_REQUIRED"


def test_manual_approval_not_required():
    result = evaluate_manual_approval_requirement(
        request(False)
    )

    assert result.approval_required is False
    assert result.manual_approval_required is False
    assert (
        result.reason
        == "MANUAL_APPROVAL_NOT_REQUIRED"
    )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_manual_approval_requirement(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_MANUAL_APPROVAL_REQUIREMENT_INPUT",
    ):
        evaluate_manual_approval_requirement({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_manual_approval_requirement(
            ManualApprovalRequirementInput(
                policy=None
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_manual_approval_requirement(
            ManualApprovalRequirementInput(
                policy={}
            )
        )


def test_policy_flag_must_be_boolean():
    with pytest.raises(
        TypeError,
        match="MANUAL_APPROVAL_REQUIRED_MUST_BE_BOOLEAN",
    ):
        evaluate_manual_approval_requirement(
            ManualApprovalRequirementInput(
                policy=make_policy(
                    manual_approval_required=1
                )
            )
        )


def test_none_policy_flag_rejected():
    with pytest.raises(
        TypeError,
        match="MANUAL_APPROVAL_REQUIRED_MUST_BE_BOOLEAN",
    ):
        evaluate_manual_approval_requirement(
            ManualApprovalRequirementInput(
                policy=make_policy(
                    manual_approval_required=None
                )
            )
        )


def test_boolean_helper_when_required():
    assert (
        is_manual_approval_required(
            request(True)
        )
        is True
    )


def test_boolean_helper_when_not_required():
    assert (
        is_manual_approval_required(
            request(False)
        )
        is False
    )


def test_public_aliases_required():
    req = request(True)
    expected = evaluate_manual_approval_requirement(req)

    assert manual_approval_requirement(req) == expected
    assert (
        check_manual_approval_requirement(req)
        == expected
    )


def test_public_aliases_not_required():
    req = request(False)
    expected = evaluate_manual_approval_requirement(req)

    assert manual_approval_requirement(req) == expected
    assert (
        check_manual_approval_requirement(req)
        == expected
    )


def test_policy_is_not_mutated():
    policy = make_policy(
        manual_approval_required=True
    )

    before = policy.manual_approval_required

    evaluate_manual_approval_requirement(
        ManualApprovalRequirementInput(
            policy=policy
        )
    )

    assert policy.manual_approval_required == before


def test_deterministic_result():
    req = request(True)

    first = evaluate_manual_approval_requirement(req)
    second = evaluate_manual_approval_requirement(req)

    assert first == second


def test_result_preserves_policy_value():
    required = evaluate_manual_approval_requirement(
        request(True)
    )

    not_required = evaluate_manual_approval_requirement(
        request(False)
    )

    assert required.manual_approval_required is True
    assert not_required.manual_approval_required is False


def test_required_and_not_required_are_distinct():
    required = evaluate_manual_approval_requirement(
        request(True)
    )

    not_required = evaluate_manual_approval_requirement(
        request(False)
    )

    assert required.approval_required is True
    assert not_required.approval_required is False
    assert required.reason != not_required.reason
