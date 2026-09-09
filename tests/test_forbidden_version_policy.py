import pytest

from sentinelshield.forbidden_version_policy import (
    ForbiddenVersionPolicyInput,
    ForbiddenVersionPolicyResult,
    check_forbidden_version,
    evaluate_forbidden_version_policy,
    forbidden_version_policy,
    is_version_forbidden,
)

from sentinelshield.remediation_policy_loading import (
    RemediationPolicy,
)


def make_policy(**overrides):
    values = {
        "policy_name": "security",
        "version": "1",
        "allowed_versions": (),
        "forbidden_versions": (
            "2.0.0",
            "2.1.0",
        ),
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


def test_forbidden_candidate_is_rejected():
    result = evaluate_forbidden_version_policy(
        ForbiddenVersionPolicyInput(
            policy=make_policy(),
            candidate_version="2.0.0",
        )
    )

    assert isinstance(
        result,
        ForbiddenVersionPolicyResult,
    )
    assert result.allowed is False
    assert result.reason == "CANDIDATE_VERSION_FORBIDDEN"


def test_non_forbidden_candidate_is_allowed():
    result = evaluate_forbidden_version_policy(
        ForbiddenVersionPolicyInput(
            policy=make_policy(),
            candidate_version="2.2.0",
        )
    )

    assert result.allowed is True
    assert result.reason == "CANDIDATE_VERSION_NOT_FORBIDDEN"


def test_empty_forbidden_list_does_not_restrict():
    result = evaluate_forbidden_version_policy(
        ForbiddenVersionPolicyInput(
            policy=make_policy(
                forbidden_versions=()
            ),
            candidate_version="9.9.9",
        )
    )

    assert result.allowed is True
    assert (
        result.reason
        == "FORBIDDEN_VERSION_POLICY_NOT_CONFIGURED"
    )


def test_candidate_whitespace_is_normalized():
    result = evaluate_forbidden_version_policy(
        ForbiddenVersionPolicyInput(
            policy=make_policy(),
            candidate_version=" 2.0.0 ",
        )
    )

    assert result.candidate_version == "2.0.0"
    assert result.allowed is False


def test_forbidden_versions_are_normalized():
    result = evaluate_forbidden_version_policy(
        ForbiddenVersionPolicyInput(
            policy=make_policy(
                forbidden_versions=(
                    " 2.0.0 ",
                    "2.1.0",
                )
            ),
            candidate_version="2.0.0",
        )
    )

    assert result.forbidden_versions == (
        "2.0.0",
        "2.1.0",
    )
    assert result.allowed is False


def test_duplicate_forbidden_versions_are_removed():
    result = evaluate_forbidden_version_policy(
        ForbiddenVersionPolicyInput(
            policy=make_policy(
                forbidden_versions=(
                    "2.0.0",
                    "2.0.0",
                    "2.1.0",
                    "2.1.0",
                )
            ),
            candidate_version="2.2.0",
        )
    )

    assert result.forbidden_versions == (
        "2.0.0",
        "2.1.0",
    )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_forbidden_version_policy(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_FORBIDDEN_VERSION_POLICY_INPUT",
    ):
        evaluate_forbidden_version_policy({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_forbidden_version_policy(
            ForbiddenVersionPolicyInput(
                policy=None,
                candidate_version="2.0.0",
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_forbidden_version_policy(
            ForbiddenVersionPolicyInput(
                policy={},
                candidate_version="2.0.0",
            )
        )


def test_candidate_version_type_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        evaluate_forbidden_version_policy(
            ForbiddenVersionPolicyInput(
                policy=make_policy(),
                candidate_version=200,
            )
        )


def test_candidate_version_empty_rejected():
    with pytest.raises(
        ValueError,
        match="CANDIDATE_VERSION_IS_EMPTY",
    ):
        evaluate_forbidden_version_policy(
            ForbiddenVersionPolicyInput(
                policy=make_policy(),
                candidate_version="   ",
            )
        )


def test_forbidden_versions_type_rejected():
    with pytest.raises(
        TypeError,
        match="FORBIDDEN_VERSIONS_MUST_BE_SEQUENCE",
    ):
        evaluate_forbidden_version_policy(
            ForbiddenVersionPolicyInput(
                policy=make_policy(
                    forbidden_versions=123
                ),
                candidate_version="2.0.0",
            )
        )


def test_forbidden_version_item_type_rejected():
    with pytest.raises(
        TypeError,
        match="FORBIDDEN_VERSIONS_ITEM_MUST_BE_STRING",
    ):
        evaluate_forbidden_version_policy(
            ForbiddenVersionPolicyInput(
                policy=make_policy(
                    forbidden_versions=(123,)
                ),
                candidate_version="2.0.0",
            )
        )


def test_forbidden_version_empty_item_rejected():
    with pytest.raises(
        ValueError,
        match="FORBIDDEN_VERSIONS_ITEM_IS_EMPTY",
    ):
        evaluate_forbidden_version_policy(
            ForbiddenVersionPolicyInput(
                policy=make_policy(
                    forbidden_versions=("",)
                ),
                candidate_version="2.0.0",
            )
        )


def test_aliases_return_same_result():
    request = ForbiddenVersionPolicyInput(
        policy=make_policy(),
        candidate_version="2.0.0",
    )

    expected = evaluate_forbidden_version_policy(
        request
    )

    assert forbidden_version_policy(request) == expected
    assert check_forbidden_version(request) == expected
    assert is_version_forbidden(request) is True


def test_is_version_forbidden_false_for_allowed_version():
    request = ForbiddenVersionPolicyInput(
        policy=make_policy(),
        candidate_version="2.2.0",
    )

    assert is_version_forbidden(request) is False


def test_policy_is_not_mutated():
    policy = make_policy(
        forbidden_versions=(
            "2.0.0",
            "2.1.0",
        )
    )

    original = policy.forbidden_versions

    evaluate_forbidden_version_policy(
        ForbiddenVersionPolicyInput(
            policy=policy,
            candidate_version="2.0.0",
        )
    )

    assert policy.forbidden_versions == original


def test_deterministic_result():
    request = ForbiddenVersionPolicyInput(
        policy=make_policy(),
        candidate_version="2.0.0",
    )

    first = evaluate_forbidden_version_policy(request)
    second = evaluate_forbidden_version_policy(request)

    assert first == second
