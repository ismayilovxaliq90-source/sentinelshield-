from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.dependency_policy_gate import (
    DependencyPolicyGateInput,
    DependencyPolicyGateResult,
    dependency_policy_gate,
    evaluate_dependency_policy_gate,
)


def make_policy(dependency_policy="direct"):
    return {"dependency_policy": dependency_policy}


def test_matching_policy_is_allowed():
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=make_policy("direct"),
            requested_dependency_policy="direct",
        )
    )

    assert result.allowed is True
    assert result.status == "DEPENDENCY_POLICY_ALLOWED"


def test_mismatching_policy_is_rejected():
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=make_policy("direct"),
            requested_dependency_policy="transitive",
        )
    )

    assert result.allowed is False
    assert result.status == "DEPENDENCY_POLICY_MISMATCH"


@pytest.mark.parametrize(
    "policy",
    [
        "direct",
        "transitive",
        "development",
        "optional",
        "peer",
        "production",
    ],
)
def test_supported_policies(policy):
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=make_policy(policy),
            requested_dependency_policy=policy,
        )
    )

    assert result.allowed is True
    assert result.status == "DEPENDENCY_POLICY_ALLOWED"


@pytest.mark.parametrize(
    "configured,requested",
    [
        ("DIRECT", "direct"),
        (" direct ", "direct"),
        ("direct-only", "direct"),
        ("direct_only", "direct"),
        ("dev", "development"),
        ("prod", "production"),
        ("transitive-only", "transitive"),
        ("optional-only", "optional"),
        ("peer-only", "peer"),
    ],
)
def test_policy_aliases(configured, requested):
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=make_policy(configured),
            requested_dependency_policy=requested,
        )
    )

    assert result.allowed is True


def test_none_gate_input():
    result = evaluate_dependency_policy_gate(None)

    assert result.allowed is False
    assert result.status == "INVALID_GATE_INPUT"


def test_wrong_gate_input_type():
    result = evaluate_dependency_policy_gate({})

    assert result.allowed is False
    assert result.status == "INVALID_GATE_INPUT"


def test_missing_policy():
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy={},
            requested_dependency_policy="direct",
        )
    )

    assert result.allowed is False
    assert result.status == "POLICY_IS_MISSING"


def test_invalid_policy():
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=make_policy("unknown"),
            requested_dependency_policy="direct",
        )
    )

    assert result.allowed is False
    assert result.status == "INVALID_POLICY"


@pytest.mark.parametrize(
    "requested",
    [None, 123, "", "unknown"],
)
def test_invalid_requested_policy(requested):
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=make_policy("direct"),
            requested_dependency_policy=requested,
        )
    )

    assert result.allowed is False
    assert result.status == "INVALID_REQUESTED_DEPENDENCY_POLICY"


def test_policy_object_attribute():
    class Policy:
        dependency_policy = "direct"

    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=Policy(),
            requested_dependency_policy="direct",
        )
    )

    assert result.allowed is True


def test_policy_key_alias():
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy={"policy": "direct"},
            requested_dependency_policy="direct",
        )
    )

    assert result.allowed is True


def test_dependency_policy_alias_function():
    data = DependencyPolicyGateInput(
        policy=make_policy("direct"),
        requested_dependency_policy="direct",
    )

    assert dependency_policy_gate(data) == (
        evaluate_dependency_policy_gate(data)
    )


def test_result_type():
    result = evaluate_dependency_policy_gate(
        DependencyPolicyGateInput(
            policy=make_policy("direct"),
            requested_dependency_policy="direct",
        )
    )

    assert isinstance(result, DependencyPolicyGateResult)


def test_input_immutable():
    value = DependencyPolicyGateInput(
        policy=make_policy("direct"),
        requested_dependency_policy="direct",
    )

    with pytest.raises(FrozenInstanceError):
        value.requested_dependency_policy = "production"


def test_result_immutable():
    value = DependencyPolicyGateResult(
        allowed=True,
        status="DEPENDENCY_POLICY_ALLOWED",
    )

    with pytest.raises(FrozenInstanceError):
        value.allowed = False
