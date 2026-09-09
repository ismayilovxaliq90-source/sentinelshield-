import pytest

from sentinelshield.development_dependency_policy import (
    DevelopmentDependencyPolicyInput,
    DevelopmentDependencyPolicyResult,
    check_development_dependency,
    development_dependency_policy,
    evaluate_development_dependency_policy,
    is_development_dependency_allowed,
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
    development=True,
    allow_development=True,
):
    return DevelopmentDependencyPolicyInput(
        policy=make_policy(
            allow_development_dependencies=allow_development
        ),
        is_development_dependency=development,
    )


def test_development_dependency_allowed():
    result = evaluate_development_dependency_policy(
        request(
            development=True,
            allow_development=True,
        )
    )

    assert isinstance(
        result,
        DevelopmentDependencyPolicyResult,
    )
    assert result.allowed is True
    assert result.is_development_dependency is True
    assert result.allow_development_dependencies is True
    assert result.reason == "DEVELOPMENT_DEPENDENCY_ALLOWED"


def test_development_dependency_forbidden():
    result = evaluate_development_dependency_policy(
        request(
            development=True,
            allow_development=False,
        )
    )

    assert result.allowed is False
    assert result.is_development_dependency is True
    assert result.allow_development_dependencies is False
    assert result.reason == "DEVELOPMENT_DEPENDENCY_FORBIDDEN"


def test_non_development_dependency_passes_gate():
    result = evaluate_development_dependency_policy(
        request(
            development=False,
            allow_development=False,
        )
    )

    assert result.allowed is True
    assert result.is_development_dependency is False
    assert result.reason == "NOT_A_DEVELOPMENT_DEPENDENCY"


def test_non_development_dependency_is_unaffected_by_policy():
    allowed = evaluate_development_dependency_policy(
        request(
            development=False,
            allow_development=True,
        )
    )

    restricted = evaluate_development_dependency_policy(
        request(
            development=False,
            allow_development=False,
        )
    )

    assert allowed.allowed is True
    assert restricted.allowed is True
    assert (
        allowed.reason
        == restricted.reason
        == "NOT_A_DEVELOPMENT_DEPENDENCY"
    )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_development_dependency_policy(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_DEVELOPMENT_DEPENDENCY_POLICY_INPUT",
    ):
        evaluate_development_dependency_policy({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_development_dependency_policy(
            DevelopmentDependencyPolicyInput(
                policy=None,
                is_development_dependency=True,
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_development_dependency_policy(
            DevelopmentDependencyPolicyInput(
                policy={},
                is_development_dependency=True,
            )
        )


def test_development_flag_must_be_boolean():
    with pytest.raises(
        TypeError,
        match="IS_DEVELOPMENT_DEPENDENCY_MUST_BE_BOOLEAN",
    ):
        evaluate_development_dependency_policy(
            DevelopmentDependencyPolicyInput(
                policy=make_policy(),
                is_development_dependency=1,
            )
        )


def test_development_flag_none_rejected():
    with pytest.raises(
        TypeError,
        match="IS_DEVELOPMENT_DEPENDENCY_MUST_BE_BOOLEAN",
    ):
        evaluate_development_dependency_policy(
            DevelopmentDependencyPolicyInput(
                policy=make_policy(),
                is_development_dependency=None,
            )
        )


def test_policy_flag_must_be_boolean():
    with pytest.raises(
        TypeError,
        match="ALLOW_DEVELOPMENT_DEPENDENCIES_MUST_BE_BOOLEAN",
    ):
        evaluate_development_dependency_policy(
            DevelopmentDependencyPolicyInput(
                policy=make_policy(
                    allow_development_dependencies=1
                ),
                is_development_dependency=True,
            )
        )


def test_policy_flag_none_rejected():
    with pytest.raises(
        TypeError,
        match="ALLOW_DEVELOPMENT_DEPENDENCIES_MUST_BE_BOOLEAN",
    ):
        evaluate_development_dependency_policy(
            DevelopmentDependencyPolicyInput(
                policy=make_policy(
                    allow_development_dependencies=None
                ),
                is_development_dependency=True,
            )
        )


def test_aliases_return_same_result():
    req = request(
        development=True,
        allow_development=False,
    )

    expected = evaluate_development_dependency_policy(req)

    assert development_dependency_policy(req) == expected
    assert check_development_dependency(req) == expected
    assert is_development_dependency_allowed(req) is False


def test_aliases_for_allowed_development_dependency():
    req = request(
        development=True,
        allow_development=True,
    )

    expected = evaluate_development_dependency_policy(req)

    assert development_dependency_policy(req) == expected
    assert check_development_dependency(req) == expected
    assert is_development_dependency_allowed(req) is True


def test_non_development_alias_returns_allowed():
    req = request(
        development=False,
        allow_development=False,
    )

    assert is_development_dependency_allowed(req) is True


def test_policy_is_not_mutated():
    policy = make_policy(
        allow_development_dependencies=False
    )

    original = policy.allow_development_dependencies

    evaluate_development_dependency_policy(
        DevelopmentDependencyPolicyInput(
            policy=policy,
            is_development_dependency=True,
        )
    )

    assert (
        policy.allow_development_dependencies
        == original
    )


def test_deterministic_result():
    req = request(
        development=True,
        allow_development=False,
    )

    first = evaluate_development_dependency_policy(req)
    second = evaluate_development_dependency_policy(req)

    assert first == second


def test_result_preserves_policy_setting():
    allowed = evaluate_development_dependency_policy(
        request(
            development=True,
            allow_development=True,
        )
    )

    forbidden = evaluate_development_dependency_policy(
        request(
            development=True,
            allow_development=False,
        )
    )

    assert allowed.allow_development_dependencies is True
    assert forbidden.allow_development_dependencies is False
