import pytest

from sentinelshield.production_dependency_policy import (
    ProductionDependencyPolicyInput,
    ProductionDependencyPolicyResult,
    check_production_dependency,
    evaluate_production_dependency_policy,
    is_production_dependency_allowed,
    production_dependency_policy,
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
    production=True,
    allow_production=True,
):
    return ProductionDependencyPolicyInput(
        policy=make_policy(
            allow_production_dependencies=allow_production
        ),
        is_production_dependency=production,
    )


def test_production_dependency_allowed():
    result = evaluate_production_dependency_policy(
        request(
            production=True,
            allow_production=True,
        )
    )

    assert isinstance(
        result,
        ProductionDependencyPolicyResult,
    )
    assert result.allowed is True
    assert result.is_production_dependency is True
    assert result.allow_production_dependencies is True
    assert result.reason == "PRODUCTION_DEPENDENCY_ALLOWED"


def test_production_dependency_forbidden():
    result = evaluate_production_dependency_policy(
        request(
            production=True,
            allow_production=False,
        )
    )

    assert result.allowed is False
    assert result.is_production_dependency is True
    assert result.allow_production_dependencies is False
    assert result.reason == "PRODUCTION_DEPENDENCY_FORBIDDEN"


def test_non_production_dependency_passes_gate():
    result = evaluate_production_dependency_policy(
        request(
            production=False,
            allow_production=False,
        )
    )

    assert result.allowed is True
    assert result.is_production_dependency is False
    assert result.reason == "NOT_A_PRODUCTION_DEPENDENCY"


def test_non_production_dependency_is_unaffected_by_policy():
    allowed = evaluate_production_dependency_policy(
        request(
            production=False,
            allow_production=True,
        )
    )

    forbidden_policy = evaluate_production_dependency_policy(
        request(
            production=False,
            allow_production=False,
        )
    )

    assert allowed.allowed is True
    assert forbidden_policy.allowed is True
    assert (
        allowed.reason
        == forbidden_policy.reason
        == "NOT_A_PRODUCTION_DEPENDENCY"
    )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_production_dependency_policy(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_PRODUCTION_DEPENDENCY_POLICY_INPUT",
    ):
        evaluate_production_dependency_policy({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_production_dependency_policy(
            ProductionDependencyPolicyInput(
                policy=None,
                is_production_dependency=True,
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_production_dependency_policy(
            ProductionDependencyPolicyInput(
                policy={},
                is_production_dependency=True,
            )
        )


def test_production_flag_must_be_boolean():
    with pytest.raises(
        TypeError,
        match="IS_PRODUCTION_DEPENDENCY_MUST_BE_BOOLEAN",
    ):
        evaluate_production_dependency_policy(
            ProductionDependencyPolicyInput(
                policy=make_policy(),
                is_production_dependency=1,
            )
        )


def test_production_flag_none_rejected():
    with pytest.raises(
        TypeError,
        match="IS_PRODUCTION_DEPENDENCY_MUST_BE_BOOLEAN",
    ):
        evaluate_production_dependency_policy(
            ProductionDependencyPolicyInput(
                policy=make_policy(),
                is_production_dependency=None,
            )
        )


def test_policy_flag_must_be_boolean():
    with pytest.raises(
        TypeError,
        match="ALLOW_PRODUCTION_DEPENDENCIES_MUST_BE_BOOLEAN",
    ):
        evaluate_production_dependency_policy(
            ProductionDependencyPolicyInput(
                policy=make_policy(
                    allow_production_dependencies=1
                ),
                is_production_dependency=True,
            )
        )


def test_policy_flag_none_rejected():
    with pytest.raises(
        TypeError,
        match="ALLOW_PRODUCTION_DEPENDENCIES_MUST_BE_BOOLEAN",
    ):
        evaluate_production_dependency_policy(
            ProductionDependencyPolicyInput(
                policy=make_policy(
                    allow_production_dependencies=None
                ),
                is_production_dependency=True,
            )
        )


def test_aliases_return_same_result():
    req = request(
        production=True,
        allow_production=False,
    )

    expected = evaluate_production_dependency_policy(req)

    assert production_dependency_policy(req) == expected
    assert check_production_dependency(req) == expected
    assert is_production_dependency_allowed(req) is False


def test_aliases_for_allowed_production_dependency():
    req = request(
        production=True,
        allow_production=True,
    )

    expected = evaluate_production_dependency_policy(req)

    assert production_dependency_policy(req) == expected
    assert check_production_dependency(req) == expected
    assert is_production_dependency_allowed(req) is True


def test_non_production_alias_returns_allowed():
    req = request(
        production=False,
        allow_production=False,
    )

    assert is_production_dependency_allowed(req) is True


def test_policy_is_not_mutated():
    policy = make_policy(
        allow_production_dependencies=False
    )

    original = policy.allow_production_dependencies

    evaluate_production_dependency_policy(
        ProductionDependencyPolicyInput(
            policy=policy,
            is_production_dependency=True,
        )
    )

    assert (
        policy.allow_production_dependencies
        == original
    )


def test_deterministic_result():
    req = request(
        production=True,
        allow_production=False,
    )

    first = evaluate_production_dependency_policy(req)
    second = evaluate_production_dependency_policy(req)

    assert first == second


def test_result_preserves_policy_setting():
    allowed = evaluate_production_dependency_policy(
        request(
            production=True,
            allow_production=True,
        )
    )

    forbidden = evaluate_production_dependency_policy(
        request(
            production=True,
            allow_production=False,
        )
    )

    assert allowed.allow_production_dependencies is True
    assert forbidden.allow_production_dependencies is False
