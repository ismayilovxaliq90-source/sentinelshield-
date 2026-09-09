from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.approved_remediation_plan import (
    ApprovedRemediationPlan,
    ApprovedRemediationPlanInput,
    ApprovedRemediationPlanResult,
    approved_remediation_plan,
    create_approved_remediation_plan,
)


def make_input(**overrides):
    values = {
        "authorization": {"authorized": True},
        "dependency_name": "requests",
        "current_version": "2.31.0",
        "target_version": "2.32.0",
        "vulnerability_ids": ["CVE-2026-0001"],
    }
    values.update(overrides)
    return ApprovedRemediationPlanInput(**values)


def test_approved_plan_is_created():
    result = create_approved_remediation_plan(make_input())

    assert result.planned is True
    assert result.status == "APPROVED_REMEDIATION_PLAN_CREATED"
    assert isinstance(result.plan, ApprovedRemediationPlan)


def test_plan_fields():
    result = create_approved_remediation_plan(
        make_input(
            dependency_name=" Flask ",
            current_version="2.3.2",
            target_version="3.0.0",
            vulnerability_ids=["cve-2", "ghsa-abcd"],
        )
    )

    assert result.plan.dependency_name == "Flask"
    assert result.plan.current_version == "2.3.2"
    assert result.plan.target_version == "3.0.0"
    assert result.plan.vulnerability_ids == (
        "CVE-2",
        "GHSA-ABCD",
    )
    assert result.plan.authorized is True


def test_unauthorized_plan_is_rejected():
    result = create_approved_remediation_plan(
        make_input(authorization={"authorized": False})
    )

    assert result.plan is None
    assert result.planned is False
    assert result.status == "REMEDIATION_NOT_AUTHORIZED"


def test_authorization_alias_allowed():
    result = create_approved_remediation_plan(
        make_input(authorization={"allowed": True})
    )

    assert result.planned is True


def test_invalid_authorization():
    result = create_approved_remediation_plan(
        make_input(authorization={"authorized": "maybe"})
    )

    assert result.planned is False
    assert result.status == "INVALID_AUTHORIZATION"


def test_none_authorization():
    result = create_approved_remediation_plan(
        make_input(authorization=None)
    )

    assert result.planned is False
    assert result.status == "INVALID_AUTHORIZATION"


def test_invalid_input_type():
    result = create_approved_remediation_plan({})

    assert result.plan is None
    assert result.planned is False
    assert result.status == "INVALID_PLAN_INPUT"


def test_none_dependency_name():
    result = create_approved_remediation_plan(
        make_input(dependency_name=None)
    )

    assert result.status == "INVALID_DEPENDENCY_NAME"


@pytest.mark.parametrize(
    "value",
    ["", "   ", 123, None],
)
def test_invalid_dependency_name(value):
    result = create_approved_remediation_plan(
        make_input(dependency_name=value)
    )

    assert result.status == "INVALID_DEPENDENCY_NAME"


@pytest.mark.parametrize(
    "field",
    ["current_version", "target_version"],
)
def test_invalid_version(field):
    result = create_approved_remediation_plan(
        make_input(**{field: None})
    )

    assert result.planned is False
    assert result.status == (
        "INVALID_CURRENT_VERSION"
        if field == "current_version"
        else "INVALID_TARGET_VERSION"
    )


def test_same_version_is_rejected():
    result = create_approved_remediation_plan(
        make_input(
            current_version="1.2.3",
            target_version="1.2.3",
        )
    )

    assert result.planned is False
    assert result.status == "TARGET_VERSION_EQUALS_CURRENT_VERSION"


def test_vulnerability_ids_are_normalized():
    result = create_approved_remediation_plan(
        make_input(
            vulnerability_ids=[
                " cve-3 ",
                "CVE-1",
                "cve-3",
            ]
        )
    )

    assert result.plan.vulnerability_ids == (
        "CVE-1",
        "CVE-3",
    )


def test_single_string_vulnerability_id():
    result = create_approved_remediation_plan(
        make_input(
            vulnerability_ids="cve-123"
        )
    )

    assert result.plan.vulnerability_ids == ("CVE-123",)


@pytest.mark.parametrize(
    "value",
    [None, [], {}, b"CVE-1", 123],
)
def test_invalid_vulnerability_ids(value):
    result = create_approved_remediation_plan(
        make_input(vulnerability_ids=value)
    )

    assert result.planned is False
    assert result.status == "INVALID_VULNERABILITY_IDS"


def test_invalid_vulnerability_id_item():
    result = create_approved_remediation_plan(
        make_input(vulnerability_ids=["CVE-1", 123])
    )

    assert result.planned is False
    assert result.status == "INVALID_VULNERABILITY_IDS"


def test_plan_is_immutable():
    result = create_approved_remediation_plan(make_input())

    with pytest.raises(FrozenInstanceError):
        result.plan.target_version = "9.9.9"


def test_result_is_immutable():
    result = create_approved_remediation_plan(make_input())

    with pytest.raises(FrozenInstanceError):
        result.planned = False


def test_result_type():
    result = create_approved_remediation_plan(make_input())

    assert isinstance(
        result,
        ApprovedRemediationPlanResult,
    )


def test_input_type():
    value = make_input()

    assert isinstance(
        value,
        ApprovedRemediationPlanInput,
    )


def test_alias_function():
    value = make_input()

    assert approved_remediation_plan(value) == (
        create_approved_remediation_plan(value)
    )


def test_deterministic_output():
    value = make_input()

    first = create_approved_remediation_plan(value)
    second = create_approved_remediation_plan(value)

    assert first == second
