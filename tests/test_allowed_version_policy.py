import pytest

from sentinelshield.allowed_version_policy import (
    AllowedVersionPolicyInput,
    AllowedVersionPolicyResult,
    allowed_version_policy,
    check_allowed_version,
    evaluate_allowed_version_policy,
    is_version_allowed,
)

from sentinelshield.remediation_policy_loading import (
    RemediationPolicy,
)


def make_policy(**overrides):
    values = {
        "policy_name": "security",
        "version": "1",
        "allowed_versions": (
            "1.2.0",
            "1.3.0",
        ),
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


def test_allowed_candidate():
    result = evaluate_allowed_version_policy(
        AllowedVersionPolicyInput(
            policy=make_policy(),
            candidate_version="1.2.0",
        )
    )

    assert isinstance(
        result,
        AllowedVersionPolicyResult,
    )
    assert result.allowed is True
    assert result.candidate_version == "1.2.0"
    assert result.reason == "CANDIDATE_VERSION_ALLOWED"


def test_disallowed_candidate():
    result = evaluate_allowed_version_policy(
        AllowedVersionPolicyInput(
            policy=make_policy(),
            candidate_version="1.4.0",
        )
    )

    assert result.allowed is False
    assert result.reason == "CANDIDATE_VERSION_NOT_ALLOWED"


def test_empty_allowed_list_does_not_restrict():
    result = evaluate_allowed_version_policy(
        AllowedVersionPolicyInput(
            policy=make_policy(
                allowed_versions=()
            ),
            candidate_version="9.9.9",
        )
    )

    assert result.allowed is True
    assert (
        result.reason
        == "ALLOWED_VERSION_POLICY_NOT_CONFIGURED"
    )


def test_duplicate_allowed_versions_are_normalized():
    result = evaluate_allowed_version_policy(
        AllowedVersionPolicyInput(
            policy=make_policy(
                allowed_versions=(
                    "1.2.0",
                    "1.2.0",
                    "1.3.0",
                )
            ),
            candidate_version="1.3.0",
        )
    )

    assert result.allowed_versions == (
        "1.2.0",
        "1.3.0",
    )


def test_candidate_whitespace_is_normalized():
    result = evaluate_allowed_version_policy(
        AllowedVersionPolicyInput(
            policy=make_policy(),
            candidate_version=" 1.2.0 ",
        )
    )

    assert result.allowed is True
    assert result.candidate_version == "1.2.0"


def test_allowed_version_whitespace_is_normalized():
    result = evaluate_allowed_version_policy(
        AllowedVersionPolicyInput(
            policy=make_policy(
                allowed_versions=(
                    " 1.2.0 ",
                    "1.3.0",
                )
            ),
            candidate_version="1.2.0",
        )
    )

    assert result.allowed is True
    assert result.allowed_versions == (
        "1.2.0",
        "1.3.0",
    )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_allowed_version_policy(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_ALLOWED_VERSION_POLICY_INPUT",
    ):
        evaluate_allowed_version_policy({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_allowed_version_policy(
            AllowedVersionPolicyInput(
                policy=None,
                candidate_version="1.2.0",
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_allowed_version_policy(
            AllowedVersionPolicyInput(
                policy={},
                candidate_version="1.2.0",
            )
        )


def test_candidate_version_type_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        evaluate_allowed_version_policy(
            AllowedVersionPolicyInput(
                policy=make_policy(),
                candidate_version=123,
            )
        )


def test_candidate_version_empty_rejected():
    with pytest.raises(
        ValueError,
        match="CANDIDATE_VERSION_IS_EMPTY",
    ):
        evaluate_allowed_version_policy(
            AllowedVersionPolicyInput(
                policy=make_policy(),
                candidate_version="   ",
            )
        )


def test_allowed_versions_type_rejected():
    with pytest.raises(
        TypeError,
        match="ALLOWED_VERSIONS_MUST_BE_SEQUENCE",
    ):
        evaluate_allowed_version_policy(
            AllowedVersionPolicyInput(
                policy=make_policy(
                    allowed_versions=123
                ),
                candidate_version="1.2.0",
            )
        )


def test_allowed_version_item_type_rejected():
    with pytest.raises(
        TypeError,
        match="ALLOWED_VERSIONS_ITEM_MUST_BE_STRING",
    ):
        evaluate_allowed_version_policy(
            AllowedVersionPolicyInput(
                policy=make_policy(
                    allowed_versions=(123,)
                ),
                candidate_version="1.2.0",
            )
        )


def test_allowed_version_empty_item_rejected():
    with pytest.raises(
        ValueError,
        match="ALLOWED_VERSIONS_ITEM_IS_EMPTY",
    ):
        evaluate_allowed_version_policy(
            AllowedVersionPolicyInput(
                policy=make_policy(
                    allowed_versions=("",)
                ),
                candidate_version="1.2.0",
            )
        )


def test_alias_function():
    request = AllowedVersionPolicyInput(
        policy=make_policy(),
        candidate_version="1.2.0",
    )

    expected = evaluate_allowed_version_policy(
        request
    )

    assert allowed_version_policy(request) == expected
    assert check_allowed_version(request) == expected
    assert is_version_allowed(request) is True


def test_deterministic_result():
    request = AllowedVersionPolicyInput(
        policy=make_policy(),
        candidate_version="1.2.0",
    )

    first = evaluate_allowed_version_policy(
        request
    )

    second = evaluate_allowed_version_policy(
        request
    )

    assert first == second


def test_policy_is_not_mutated():
    policy = make_policy(
        allowed_versions=(
            "1.2.0",
            "1.3.0",
        )
    )

    original = policy.allowed_versions

    evaluate_allowed_version_policy(
        AllowedVersionPolicyInput(
            policy=policy,
            candidate_version="1.2.0",
        )
    )

    assert policy.allowed_versions == original
