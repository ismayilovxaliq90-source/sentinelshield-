from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.remediation_authorization import (
    RemediationAuthorizationInput,
    RemediationAuthorizationResult,
    authorize_remediation,
    remediation_authorization,
)


def make_input(**overrides):
    values = {
        "policy_valid": True,
        "security_policy_valid": True,
        "version_policy_allowed": True,
        "automated_remediation_eligible": True,
        "manual_approval_required": False,
        "risk_threshold_passed": True,
        "change_scope_allowed": True,
        "dependency_policy_allowed": True,
    }
    values.update(overrides)
    return RemediationAuthorizationInput(**values)


def test_all_gates_pass():
    result = authorize_remediation(make_input())

    assert result.authorized is True
    assert result.status == "REMEDIATION_AUTHORIZED"
    assert result.reasons == ("ALL_AUTHORIZATION_GATES_PASSED",)


@pytest.mark.parametrize(
    "field,reason",
    [
        ("policy_valid", "POLICY_INVALID"),
        ("security_policy_valid", "SECURITY_POLICY_INVALID"),
        ("version_policy_allowed", "VERSION_POLICY_NOT_ALLOWED"),
        (
            "automated_remediation_eligible",
            "AUTOMATED_REMEDIATION_NOT_ELIGIBLE",
        ),
        ("risk_threshold_passed", "RISK_THRESHOLD_NOT_PASSED"),
        ("change_scope_allowed", "CHANGE_SCOPE_NOT_ALLOWED"),
        (
            "dependency_policy_allowed",
            "DEPENDENCY_POLICY_NOT_ALLOWED",
        ),
    ],
)
def test_failed_gate_denies_authorization(field, reason):
    result = authorize_remediation(
        make_input(**{field: False})
    )

    assert result.authorized is False
    assert result.status == "REMEDIATION_NOT_AUTHORIZED"
    assert reason in result.reasons


def test_manual_approval_required_denies_automatic_authorization():
    result = authorize_remediation(
        make_input(manual_approval_required=True)
    )

    assert result.authorized is False
    assert result.status == "REMEDIATION_NOT_AUTHORIZED"
    assert "MANUAL_APPROVAL_REQUIRED" in result.reasons


def test_multiple_failed_gates_are_reported():
    result = authorize_remediation(
        make_input(
            policy_valid=False,
            risk_threshold_passed=False,
            change_scope_allowed=False,
        )
    )

    assert result.authorized is False
    assert result.status == "REMEDIATION_NOT_AUTHORIZED"
    assert result.reasons == (
        "POLICY_INVALID",
        "RISK_THRESHOLD_NOT_PASSED",
        "CHANGE_SCOPE_NOT_ALLOWED",
    )


def test_none_input():
    result = authorize_remediation(None)

    assert result.authorized is False
    assert result.status == "INVALID_AUTHORIZATION_INPUT"
    assert result.reasons == ("INVALID_INPUT_TYPE",)


def test_wrong_input_type():
    result = authorize_remediation({})

    assert result.authorized is False
    assert result.status == "INVALID_AUTHORIZATION_INPUT"


@pytest.mark.parametrize(
    "value",
    [None, 2, -1, object(), "maybe"],
)
def test_invalid_policy_signal(value):
    result = authorize_remediation(
        make_input(policy_valid=value)
    )

    assert result.authorized is False
    assert result.status == "INVALID_AUTHORIZATION_SIGNAL"
    assert result.reasons == ("INVALID_POLICY_VALID",)


@pytest.mark.parametrize(
    "value",
    [True, 1, "true", "YES", "allowed", "pass", "valid"],
)
def test_true_normalization(value):
    result = authorize_remediation(
        make_input(policy_valid=value)
    )

    assert result.authorized is True


@pytest.mark.parametrize(
    "value",
    [False, 0, "false", "NO", "denied", "fail", "invalid"],
)
def test_false_normalization(value):
    result = authorize_remediation(
        make_input(policy_valid=value)
    )

    assert result.authorized is False
    assert result.status == "REMEDIATION_NOT_AUTHORIZED"


def test_all_string_signals():
    result = authorize_remediation(
        make_input(
            policy_valid="valid",
            security_policy_valid="valid",
            version_policy_allowed="allowed",
            automated_remediation_eligible="eligible",
            manual_approval_required=False,
            risk_threshold_passed="passed",
            change_scope_allowed="allowed",
            dependency_policy_allowed="allowed",
        )
    )

    assert result.authorized is True


def test_result_type():
    result = authorize_remediation(make_input())

    assert isinstance(result, RemediationAuthorizationResult)


def test_input_type():
    value = make_input()

    assert isinstance(
        value,
        RemediationAuthorizationInput,
    )


def test_input_immutable():
    value = make_input()

    with pytest.raises(FrozenInstanceError):
        value.policy_valid = False


def test_result_immutable():
    result = authorize_remediation(make_input())

    with pytest.raises(FrozenInstanceError):
        result.authorized = False


def test_alias_function():
    value = make_input()

    assert remediation_authorization(value) == (
        authorize_remediation(value)
    )


def test_authorization_is_deterministic():
    value = make_input()

    first = authorize_remediation(value)
    second = authorize_remediation(value)

    assert first == second
