import pytest

from sentinelshield.maximum_upgrade_distance_policy import (
    MaximumUpgradeDistancePolicyInput,
    MaximumUpgradeDistancePolicyResult,
    check_maximum_upgrade_distance,
    evaluate_maximum_upgrade_distance_policy,
    is_upgrade_distance_allowed,
    maximum_upgrade_distance_policy,
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
        "maximum_upgrade_distance": 1_000_000,
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
    candidate="1.2.4",
    maximum=1_000_000,
):
    return MaximumUpgradeDistancePolicyInput(
        policy=make_policy(
            maximum_upgrade_distance=maximum
        ),
        current_version=current,
        candidate_version=candidate,
    )


def test_patch_upgrade_within_limit():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3",
            candidate="1.2.4",
            maximum=1,
        )
    )

    assert isinstance(
        result,
        MaximumUpgradeDistancePolicyResult,
    )
    assert result.allowed is True
    assert result.upgrade_distance == 1
    assert result.reason == "UPGRADE_DISTANCE_WITHIN_MAXIMUM"


def test_patch_upgrade_over_limit():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3",
            candidate="1.2.8",
            maximum=4,
        )
    )

    assert result.allowed is False
    assert result.upgrade_distance == 5
    assert result.reason == "UPGRADE_DISTANCE_EXCEEDS_MAXIMUM"


def test_minor_upgrade_distance():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3",
            candidate="1.3.3",
            maximum=1_000,
        )
    )

    assert result.upgrade_distance == 1_000
    assert result.allowed is True


def test_major_upgrade_distance():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3",
            candidate="2.2.3",
            maximum=1_000_000,
        )
    )

    assert result.upgrade_distance == 1_000_000
    assert result.allowed is True


def test_major_upgrade_over_limit():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3",
            candidate="2.0.0",
            maximum=997_996,
        )
    )

    assert result.allowed is False
    assert result.reason == "UPGRADE_DISTANCE_EXCEEDS_MAXIMUM"


def test_equal_version_is_not_upgrade():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3",
            candidate="1.2.3",
            maximum=100,
        )
    )

    assert result.allowed is False
    assert result.upgrade_distance == 0
    assert result.reason == "CANDIDATE_IS_NOT_AN_UPGRADE"


def test_downgrade_is_not_upgrade():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3",
            candidate="1.2.2",
            maximum=100,
        )
    )

    assert result.allowed is False
    assert result.upgrade_distance == -1
    assert result.reason == "CANDIDATE_IS_NOT_AN_UPGRADE"


def test_none_maximum_means_no_distance_restriction():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.0.0",
            candidate="10.0.0",
            maximum=None,
        )
    )

    assert result.allowed is True
    assert result.maximum_upgrade_distance is None
    assert (
        result.reason
        == "MAXIMUM_UPGRADE_DISTANCE_POLICY_NOT_CONFIGURED"
    )


def test_zero_maximum_rejects_any_upgrade():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.0.0",
            candidate="1.0.1",
            maximum=0,
        )
    )

    assert result.allowed is False
    assert result.reason == "UPGRADE_DISTANCE_EXCEEDS_MAXIMUM"


def test_boundary_value_is_allowed():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.0.0",
            candidate="1.0.5",
            maximum=5,
        )
    )

    assert result.allowed is True
    assert result.upgrade_distance == 5


def test_v_prefix_is_supported():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="v1.2.3",
            candidate="V1.2.4",
            maximum=1,
        )
    )

    assert result.allowed is True
    assert result.upgrade_distance == 1


def test_missing_minor_and_patch_are_padded():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1",
            candidate="1.1",
            maximum=1_000,
        )
    )

    assert result.allowed is True
    assert result.upgrade_distance == 1_000


def test_suffixes_do_not_change_distance():
    result = evaluate_maximum_upgrade_distance_policy(
        request(
            current="1.2.3-beta",
            candidate="1.2.4+build",
            maximum=1,
        )
    )

    assert result.allowed is True
    assert result.upgrade_distance == 1


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        evaluate_maximum_upgrade_distance_policy(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_MAXIMUM_UPGRADE_DISTANCE_POLICY_INPUT",
    ):
        evaluate_maximum_upgrade_distance_policy({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        evaluate_maximum_upgrade_distance_policy(
            MaximumUpgradeDistancePolicyInput(
                policy=None,
                current_version="1.0.0",
                candidate_version="1.0.1",
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        evaluate_maximum_upgrade_distance_policy(
            MaximumUpgradeDistancePolicyInput(
                policy={},
                current_version="1.0.0",
                candidate_version="1.0.1",
            )
        )


def test_current_version_type_rejected():
    with pytest.raises(
        TypeError,
        match="CURRENT_VERSION_MUST_BE_STRING",
    ):
        evaluate_maximum_upgrade_distance_policy(
            MaximumUpgradeDistancePolicyInput(
                policy=make_policy(),
                current_version=100,
                candidate_version="1.0.1",
            )
        )


def test_candidate_version_type_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        evaluate_maximum_upgrade_distance_policy(
            MaximumUpgradeDistancePolicyInput(
                policy=make_policy(),
                current_version="1.0.0",
                candidate_version=101,
            )
        )


def test_empty_current_version_rejected():
    with pytest.raises(
        ValueError,
        match="CURRENT_VERSION_IS_EMPTY",
    ):
        evaluate_maximum_upgrade_distance_policy(
            request(
                current="   ",
                candidate="1.0.1",
            )
        )


def test_empty_candidate_version_rejected():
    with pytest.raises(
        ValueError,
        match="CANDIDATE_VERSION_IS_EMPTY",
    ):
        evaluate_maximum_upgrade_distance_policy(
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
        evaluate_maximum_upgrade_distance_policy(
            request(
                current="1.x.0",
                candidate="1.1.0",
            )
        )


def test_invalid_candidate_version_rejected():
    with pytest.raises(
        ValueError,
        match="CANDIDATE_VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        evaluate_maximum_upgrade_distance_policy(
            request(
                current="1.0.0",
                candidate="1.x.0",
            )
        )


def test_negative_maximum_rejected():
    with pytest.raises(
        ValueError,
        match="MAXIMUM_UPGRADE_DISTANCE_MUST_BE_NONNEGATIVE",
    ):
        evaluate_maximum_upgrade_distance_policy(
            request(
                current="1.0.0",
                candidate="1.0.1",
                maximum=-1,
            )
        )


def test_boolean_maximum_rejected():
    with pytest.raises(
        TypeError,
        match="MAXIMUM_UPGRADE_DISTANCE_MUST_BE_INTEGER",
    ):
        evaluate_maximum_upgrade_distance_policy(
            request(
                current="1.0.0",
                candidate="1.0.1",
                maximum=True,
            )
        )


def test_non_integer_maximum_rejected():
    with pytest.raises(
        TypeError,
        match="MAXIMUM_UPGRADE_DISTANCE_MUST_BE_INTEGER",
    ):
        evaluate_maximum_upgrade_distance_policy(
            request(
                current="1.0.0",
                candidate="1.0.1",
                maximum=1.5,
            )
        )


def test_aliases_return_same_result():
    req = request(
        current="1.2.3",
        candidate="1.2.5",
        maximum=2,
    )

    expected = evaluate_maximum_upgrade_distance_policy(req)

    assert maximum_upgrade_distance_policy(req) == expected
    assert check_maximum_upgrade_distance(req) == expected
    assert is_upgrade_distance_allowed(req) is True


def test_policy_is_not_mutated():
    policy = make_policy(
        maximum_upgrade_distance=10
    )

    original = policy.maximum_upgrade_distance

    evaluate_maximum_upgrade_distance_policy(
        MaximumUpgradeDistancePolicyInput(
            policy=policy,
            current_version="1.0.0",
            candidate_version="1.0.1",
        )
    )

    assert policy.maximum_upgrade_distance == original


def test_deterministic_result():
    req = request(
        current="1.2.3",
        candidate="1.4.0",
        maximum=2_000,
    )

    first = evaluate_maximum_upgrade_distance_policy(req)
    second = evaluate_maximum_upgrade_distance_policy(req)

    assert first == second
