import pytest

from sentinelshield.major_upgrade_policy import (
    MajorUpgradePolicyInput,
    MajorUpgradePolicyResult,
    check_major_upgrade,
    evaluate_major_upgrade_policy,
    is_major_upgrade_allowed,
    major_upgrade_policy,
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
    current="1.2.3",
    candidate="2.0.0",
    allow_major=False,
):
    return MajorUpgradePolicyInput(
        policy=make_policy(
            allow_major_upgrades=allow_major
        ),
        current_version=current,
        candidate_version=candidate,
    )


def test_major_upgrade_forbidden_by_default():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.2.3",
            candidate="2.0.0",
            allow_major=False,
        )
    )

    assert isinstance(
        result,
        MajorUpgradePolicyResult,
    )
    assert result.is_upgrade is True
    assert result.is_major_upgrade is True
    assert result.allowed is False
    assert result.reason == "MAJOR_UPGRADE_FORBIDDEN"


def test_major_upgrade_allowed_when_policy_enabled():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.2.3",
            candidate="2.0.0",
            allow_major=True,
        )
    )

    assert result.allowed is True
    assert result.is_upgrade is True
    assert result.is_major_upgrade is True
    assert result.reason == "MAJOR_UPGRADE_ALLOWED"


def test_minor_upgrade_is_not_major():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.2.3",
            candidate="1.3.0",
            allow_major=False,
        )
    )

    assert result.allowed is True
    assert result.is_upgrade is True
    assert result.is_major_upgrade is False
    assert result.reason == "NON_MAJOR_UPGRADE_ALLOWED"


def test_patch_upgrade_is_not_major():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.2.3",
            candidate="1.2.4",
            allow_major=False,
        )
    )

    assert result.allowed is True
    assert result.is_upgrade is True
    assert result.is_major_upgrade is False


def test_equal_version_is_not_upgrade():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.2.3",
            candidate="1.2.3",
            allow_major=True,
        )
    )

    assert result.allowed is False
    assert result.is_upgrade is False
    assert result.is_major_upgrade is False
    assert result.reason == "CANDIDATE_IS_NOT_AN_UPGRADE"


def test_downgrade_is_not_upgrade():
    result = evaluate_major_upgrade_policy(
        request(
            current="2.0.0",
            candidate="1.9.9",
            allow_major=True,
        )
    )

    assert result.allowed is False
    assert result.is_upgrade is False
    assert result.is_major_upgrade is False


def test_multiple_major_upgrade_is_forbidden():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.0.0",
            candidate="5.0.0",
            allow_major=False,
        )
    )

    assert result.allowed is False
    assert result.is_major_upgrade is True


def test_multiple_major_upgrade_is_allowed():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.0.0",
            candidate="5.0.0",
            allow_major=True,
        )
    )

    assert result.allowed is True
    assert result.is_major_upgrade is True


def test_v_prefix_supported():
    result = evaluate_major_upgrade_policy(
        request(
            current="v1.2.3",
            candidate="V2.0.0",
            allow_major=False,
        )
    )

    assert result.allowed is False
    assert result.is_major_upgrade is True


def test_suffixes_ignored_for_major_comparison():
    result = evaluate_major_upgrade_policy(
        request(
            current="1.2.3-beta",
            candidate="2.0.0+build",
            allow_major=False,
        )
    )

    assert result.is_major_upgrade is True
    assert result.allowed is False


def test_missing_components_are_padded():
    result = evaluate_major_upgrade_policy(
        request(
            current="1",
            candidate="2",
            allow_major=False,
        )
    )

    assert result.is_upgrade is True
    assert result.is_major_upgrade is True
    assert result.allowed is False


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_major_upgrade_policy(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_MAJOR_UPGRADE_POLICY_INPUT",
    ):
        evaluate_major_upgrade_policy({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_major_upgrade_policy(
            MajorUpgradePolicyInput(
                policy=None,
                current_version="1.0.0",
                candidate_version="2.0.0",
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_major_upgrade_policy(
            MajorUpgradePolicyInput(
                policy={},
                current_version="1.0.0",
                candidate_version="2.0.0",
            )
        )


def test_current_version_type_rejected():
    with pytest.raises(
        TypeError,
        match="CURRENT_VERSION_MUST_BE_STRING",
    ):
        evaluate_major_upgrade_policy(
            MajorUpgradePolicyInput(
                policy=make_policy(),
                current_version=100,
                candidate_version="2.0.0",
            )
        )


def test_candidate_version_type_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        evaluate_major_upgrade_policy(
            MajorUpgradePolicyInput(
                policy=make_policy(),
                current_version="1.0.0",
                candidate_version=200,
            )
        )


def test_empty_current_version_rejected():
    with pytest.raises(
        ValueError,
        match="CURRENT_VERSION_IS_EMPTY",
    ):
        evaluate_major_upgrade_policy(
            request(
                current="   ",
                candidate="2.0.0",
            )
        )


def test_empty_candidate_version_rejected():
    with pytest.raises(
        ValueError,
        match="CANDIDATE_VERSION_IS_EMPTY",
    ):
        evaluate_major_upgrade_policy(
            request(
                current="1.0.0",
                candidate="   ",
            )
        )


def test_invalid_current_version_rejected():
    with pytest.raises(
        ValueError,
        match="CURRENT_VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        evaluate_major_upgrade_policy(
            request(
                current="1.x.0",
                candidate="2.0.0",
            )
        )


def test_invalid_candidate_version_rejected():
    with pytest.raises(
        ValueError,
        match="CANDIDATE_VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        evaluate_major_upgrade_policy(
            request(
                current="1.0.0",
                candidate="2.x.0",
            )
        )


def test_aliases_return_same_result():
    req = request(
        current="1.2.3",
        candidate="2.0.0",
        allow_major=False,
    )

    expected = evaluate_major_upgrade_policy(req)

    assert major_upgrade_policy(req) == expected
    assert check_major_upgrade(req) == expected
    assert is_major_upgrade_allowed(req) is False


def test_aliases_for_allowed_major_upgrade():
    req = request(
        current="1.2.3",
        candidate="2.0.0",
        allow_major=True,
    )

    expected = evaluate_major_upgrade_policy(req)

    assert major_upgrade_policy(req) == expected
    assert check_major_upgrade(req) == expected
    assert is_major_upgrade_allowed(req) is True


def test_policy_is_not_mutated():
    policy = make_policy(
        allow_major_upgrades=False
    )

    original = policy.allow_major_upgrades

    evaluate_major_upgrade_policy(
        MajorUpgradePolicyInput(
            policy=policy,
            current_version="1.0.0",
            candidate_version="2.0.0",
        )
    )

    assert policy.allow_major_upgrades == original


def test_deterministic_result():
    req = request(
        current="1.2.3",
        candidate="2.0.0",
        allow_major=False,
    )

    first = evaluate_major_upgrade_policy(req)
    second = evaluate_major_upgrade_policy(req)

    assert first == second
