import pytest

from sentinelshield.remediation_policy_loading import (
    RemediationPolicy,
)

from sentinelshield.security_policy_validation import (
    SecurityPolicyValidationInput,
    SecurityPolicyValidationResult,
    check_security_policy,
    is_security_policy_valid,
    security_policy_validation,
    validate_security_policy,
)


def make_policy(**overrides):
    values = {
        "policy_name": "security",
        "version": "1",
        "allowed_versions": (
            "1.2.0",
            "1.3.0",
        ),
        "forbidden_versions": (
            "2.0.0",
        ),
        "maximum_upgrade_distance": 5,
        "allow_major_upgrades": False,
        "allow_production_dependencies": True,
        "allow_development_dependencies": True,
        "automated_remediation": False,
        "manual_approval_required": True,
        "risk_threshold": 40.0,
        "change_scope": "DEPENDENCY",
        "dependency_policy": "STRICT",
    }

    values.update(overrides)

    return RemediationPolicy(**values)


def test_valid_policy():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy()
        )
    )

    assert isinstance(
        result,
        SecurityPolicyValidationResult,
    )
    assert result.valid is True
    assert result.errors == ()
    assert "SECURITY_POLICY_VALID" in result.reasons


def test_version_conflict_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                allowed_versions=("1.2.0",),
                forbidden_versions=("1.2.0",),
            )
        )
    )

    assert result.valid is False
    assert (
        "ALLOWED_FORBIDDEN_VERSION_CONFLICT"
        in result.errors
    )


def test_major_upgrade_restriction_is_reported():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                allow_major_upgrades=False
            )
        )
    )

    assert result.valid is True
    assert (
        "MAJOR_UPGRADES_RESTRICTED"
        in result.reasons
    )


def test_major_upgrade_allowed_is_reported():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                allow_major_upgrades=True
            )
        )
    )

    assert result.valid is True
    assert (
        "MAJOR_UPGRADES_ALLOWED"
        in result.reasons
    )


def test_automated_remediation_requires_approval():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                automated_remediation=True,
                manual_approval_required=True,
            )
        )
    )

    assert result.valid is True
    assert (
        "AUTOMATED_REMEDIATION_REQUIRES_APPROVAL"
        in result.reasons
    )


def test_fully_automated_policy_is_allowed():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                automated_remediation=True,
                manual_approval_required=False,
            )
        )
    )

    assert result.valid is True
    assert (
        "AUTOMATED_REMEDIATION_ALLOWED"
        in result.reasons
    )


def test_risk_threshold_zero_allowed():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                risk_threshold=0
            )
        )
    )

    assert result.valid is True


def test_risk_threshold_100_allowed():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                risk_threshold=100
            )
        )
    )

    assert result.valid is True


def test_risk_threshold_above_range_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                risk_threshold=101
            )
        )
    )

    assert result.valid is False
    assert (
        "RISK_THRESHOLD_OUT_OF_RANGE"
        in result.errors
    )


def test_risk_threshold_below_range_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                risk_threshold=-1
            )
        )
    )

    assert result.valid is False
    assert (
        "RISK_THRESHOLD_OUT_OF_RANGE"
        in result.errors
    )


def test_negative_upgrade_distance_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                maximum_upgrade_distance=-1
            )
        )
    )

    assert result.valid is False
    assert (
        "MAXIMUM_UPGRADE_DISTANCE_MUST_BE_NON_NEGATIVE"
        in result.errors
    )


def test_zero_upgrade_distance_allowed():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                maximum_upgrade_distance=0
            )
        )
    )

    assert result.valid is True


def test_production_dependency_restriction():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                allow_production_dependencies=False
            )
        )
    )

    assert result.valid is True
    assert (
        "PRODUCTION_DEPENDENCIES_RESTRICTED"
        in result.reasons
    )


def test_development_dependency_restriction():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                allow_development_dependencies=False
            )
        )
    )

    assert result.valid is True
    assert (
        "DEVELOPMENT_DEPENDENCIES_RESTRICTED"
        in result.reasons
    )


def test_empty_policy_name_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                policy_name=""
            )
        )
    )

    assert result.valid is False
    assert "POLICY_NAME_IS_EMPTY" in result.errors


def test_empty_version_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                version=""
            )
        )
    )

    assert result.valid is False
    assert "VERSION_IS_EMPTY" in result.errors


def test_empty_change_scope_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                change_scope=""
            )
        )
    )

    assert result.valid is False
    assert "CHANGE_SCOPE_IS_EMPTY" in result.errors


def test_empty_dependency_policy_rejected():
    result = validate_security_policy(
        SecurityPolicyValidationInput(
            policy=make_policy(
                dependency_policy=""
            )
        )
    )

    assert result.valid is False
    assert (
        "DEPENDENCY_POLICY_IS_EMPTY"
        in result.errors
    )


def test_none_input_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_IS_NONE",
    ):
        validate_security_policy(None)


def test_invalid_input_type_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_SECURITY_POLICY_VALIDATION_INPUT",
    ):
        validate_security_policy({})


def test_none_policy_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_IS_NONE",
    ):
        validate_security_policy(
            SecurityPolicyValidationInput(
                policy=None
            )
        )


def test_invalid_policy_type_rejected():
    with pytest.raises(
        TypeError,
        match="POLICY_MUST_BE_REMEDIATION_POLICY",
    ):
        validate_security_policy(
            SecurityPolicyValidationInput(
                policy={}
            )
        )


def test_aliases():
    request = SecurityPolicyValidationInput(
        policy=make_policy()
    )

    assert (
        security_policy_validation(request)
        == validate_security_policy(request)
    )

    assert (
        check_security_policy(request)
        == validate_security_policy(request)
    )

    assert (
        is_security_policy_valid(request)
        is True
    )


def test_deterministic_result():
    request = SecurityPolicyValidationInput(
        policy=make_policy()
    )

    first = validate_security_policy(request)
    second = validate_security_policy(request)

    assert first == second
