import pytest

from sentinelshield.change_scope_gate import (
    ChangeScopeGateInput,
    ChangeScopeGateResult,
    change_scope_gate,
    check_change_scope,
    evaluate_change_scope_gate,
    is_change_scope_allowed,
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
    requested_scope="DEPENDENCY",
    policy_scope="DEPENDENCY",
):
    return ChangeScopeGateInput(
        policy=make_policy(
            change_scope=policy_scope
        ),
        requested_change_scope=requested_scope,
    )


def test_matching_change_scope_is_allowed():
    result = evaluate_change_scope_gate(
        request(
            requested_scope="DEPENDENCY",
            policy_scope="DEPENDENCY",
        )
    )

    assert isinstance(
        result,
        ChangeScopeGateResult,
    )
    assert result.allowed is True
    assert result.requested_change_scope == "dependency"
    assert result.policy_change_scope == "dependency"
    assert result.reason == "CHANGE_SCOPE_ALLOWED"


def test_different_change_scope_is_forbidden():
    result = evaluate_change_scope_gate(
        request(
            requested_scope="CONFIGURATION",
            policy_scope="DEPENDENCY",
        )
    )

    assert result.allowed is False
    assert result.requested_change_scope == "configuration"
    assert result.policy_change_scope == "dependency"
    assert result.reason == "CHANGE_SCOPE_FORBIDDEN"


def test_scope_comparison_is_case_insensitive():
    result = evaluate_change_scope_gate(
        request(
            requested_scope="dependency",
            policy_scope="DEPENDENCY",
        )
    )

    assert result.allowed is True


def test_scope_whitespace_is_ignored():
    result = evaluate_change_scope_gate(
        request(
            requested_scope="  DEPENDENCY  ",
            policy_scope="  dependency ",
        )
    )

    assert result.allowed is True
    assert result.requested_change_scope == "dependency"
    assert result.policy_change_scope == "dependency"


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_change_scope_gate(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_CHANGE_SCOPE_GATE_INPUT",
    ):
        evaluate_change_scope_gate({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_change_scope_gate(
            ChangeScopeGateInput(
                policy=None,
                requested_change_scope="DEPENDENCY",
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_change_scope_gate(
            ChangeScopeGateInput(
                policy={},
                requested_change_scope="DEPENDENCY",
            )
        )


@pytest.mark.parametrize(
    "value",
    [None, 1, True, [], {}, b"DEPENDENCY"],
)
def test_requested_scope_must_be_string(value):
    with pytest.raises(
        TypeError,
        match="REQUESTED_CHANGE_SCOPE_MUST_BE_STRING",
    ):
        evaluate_change_scope_gate(
            request(
                requested_scope=value
            )
        )


@pytest.mark.parametrize(
    "value",
    ["", "   "],
)
def test_requested_scope_cannot_be_empty(value):
    with pytest.raises(
        ValueError,
        match="REQUESTED_CHANGE_SCOPE_IS_EMPTY",
    ):
        evaluate_change_scope_gate(
            request(
                requested_scope=value
            )
        )


@pytest.mark.parametrize(
    "value",
    [None, 1, True, [], {}, b"DEPENDENCY"],
)
def test_policy_scope_must_be_string(value):
    with pytest.raises(
        TypeError,
        match="POLICY_CHANGE_SCOPE_MUST_BE_STRING",
    ):
        evaluate_change_scope_gate(
            request(
                requested_scope="DEPENDENCY",
                policy_scope=value,
            )
        )


@pytest.mark.parametrize(
    "value",
    ["", "   "],
)
def test_policy_scope_cannot_be_empty(value):
    with pytest.raises(
        ValueError,
        match="POLICY_CHANGE_SCOPE_IS_EMPTY",
    ):
        evaluate_change_scope_gate(
            request(
                requested_scope="DEPENDENCY",
                policy_scope=value,
            )
        )


def test_multiple_different_scopes_are_forbidden():
    for requested_scope in (
        "CONFIGURATION",
        "RUNTIME",
        "FILESYSTEM",
        "APPLICATION",
    ):
        result = evaluate_change_scope_gate(
            request(
                requested_scope=requested_scope,
                policy_scope="DEPENDENCY",
            )
        )

        assert result.allowed is False
        assert result.reason == "CHANGE_SCOPE_FORBIDDEN"


def test_matching_non_default_scope_is_allowed():
    result = evaluate_change_scope_gate(
        request(
            requested_scope="RUNTIME",
            policy_scope="runtime",
        )
    )

    assert result.allowed is True
    assert result.reason == "CHANGE_SCOPE_ALLOWED"


def test_boolean_helper_allowed():
    assert (
        is_change_scope_allowed(
            request(
                requested_scope="DEPENDENCY",
                policy_scope="DEPENDENCY",
            )
        )
        is True
    )


def test_boolean_helper_forbidden():
    assert (
        is_change_scope_allowed(
            request(
                requested_scope="RUNTIME",
                policy_scope="DEPENDENCY",
            )
        )
        is False
    )


def test_public_aliases_allowed():
    req = request(
        requested_scope="DEPENDENCY",
        policy_scope="DEPENDENCY",
    )

    expected = evaluate_change_scope_gate(req)

    assert change_scope_gate(req) == expected
    assert check_change_scope(req) == expected


def test_public_aliases_forbidden():
    req = request(
        requested_scope="RUNTIME",
        policy_scope="DEPENDENCY",
    )

    expected = evaluate_change_scope_gate(req)

    assert change_scope_gate(req) == expected
    assert check_change_scope(req) == expected


def test_policy_is_not_mutated():
    policy = make_policy(
        change_scope="DEPENDENCY"
    )

    before = policy.change_scope

    evaluate_change_scope_gate(
        ChangeScopeGateInput(
            policy=policy,
            requested_change_scope="DEPENDENCY",
        )
    )

    assert policy.change_scope == before


def test_deterministic_result():
    req = request(
        requested_scope="DEPENDENCY",
        policy_scope="DEPENDENCY",
    )

    first = evaluate_change_scope_gate(req)
    second = evaluate_change_scope_gate(req)

    assert first == second


def test_result_contains_normalized_scopes():
    result = evaluate_change_scope_gate(
        request(
            requested_scope="  Dependency ",
            policy_scope=" DEPENDENCY ",
        )
    )

    assert result.requested_change_scope == "dependency"
    assert result.policy_change_scope == "dependency"


def test_gate_does_not_depend_on_other_policy_flags():
    policy = make_policy(
        change_scope="DEPENDENCY",
        automated_remediation=True,
        manual_approval_required=False,
        allow_major_upgrades=True,
        allow_production_dependencies=False,
        allow_development_dependencies=False,
        risk_threshold=90.0,
    )

    result = evaluate_change_scope_gate(
        ChangeScopeGateInput(
            policy=policy,
            requested_change_scope="DEPENDENCY",
        )
    )

    assert result.allowed is True
    assert result.reason == "CHANGE_SCOPE_ALLOWED"
