from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApprovedRemediationPlanInput:
    authorization: Any
    dependency_name: Any
    current_version: Any
    target_version: Any
    vulnerability_ids: Any


@dataclass(frozen=True)
class ApprovedRemediationPlan:
    dependency_name: str
    current_version: str
    target_version: str
    vulnerability_ids: tuple[str, ...]
    authorized: bool


@dataclass(frozen=True)
class ApprovedRemediationPlanResult:
    plan: ApprovedRemediationPlan | None
    planned: bool
    status: str


def _read(value: Any, names: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        for name in names:
            if name in value:
                return value[name]
        return None

    for name in names:
        try:
            return getattr(value, name)
        except AttributeError:
            continue

    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    if isinstance(value, int) and value in (0, 1):
        return bool(value)

    if isinstance(value, str):
        value = value.strip().lower()

        if value in {"true", "yes", "allowed", "authorized", "approved"}:
            return True

        if value in {"false", "no", "denied", "unauthorized", "rejected"}:
            return False

    return None


def _normalize_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()

    return value or None


def _normalize_identifier(value: Any) -> str | None:
    value = _normalize_text(value)

    if value is None:
        return None

    return value.upper()


def _normalize_vulnerability_ids(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str):
        value = (value,)

    elif isinstance(value, (bytes, bytearray, dict)):
        return None

    try:
        values = tuple(value)
    except TypeError:
        return None

    if not values:
        return None

    normalized: list[str] = []

    for item in values:
        identifier = _normalize_identifier(item)

        if identifier is None:
            return None

        normalized.append(identifier)

    return tuple(sorted(set(normalized)))


def create_approved_remediation_plan(
    plan_input: ApprovedRemediationPlanInput,
) -> ApprovedRemediationPlanResult:
    if not isinstance(
        plan_input,
        ApprovedRemediationPlanInput,
    ):
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="INVALID_PLAN_INPUT",
        )

    authorization_value = _read(
        plan_input.authorization,
        ("authorized", "allowed"),
    )

    authorization = _as_bool(authorization_value)

    if authorization is None:
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="INVALID_AUTHORIZATION",
        )

    if authorization is False:
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="REMEDIATION_NOT_AUTHORIZED",
        )

    dependency_name = _normalize_text(
        plan_input.dependency_name
    )

    if dependency_name is None:
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="INVALID_DEPENDENCY_NAME",
        )

    current_version = _normalize_text(
        plan_input.current_version
    )

    if current_version is None:
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="INVALID_CURRENT_VERSION",
        )

    target_version = _normalize_text(
        plan_input.target_version
    )

    if target_version is None:
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="INVALID_TARGET_VERSION",
        )

    if current_version == target_version:
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="TARGET_VERSION_EQUALS_CURRENT_VERSION",
        )

    vulnerability_ids = _normalize_vulnerability_ids(
        plan_input.vulnerability_ids
    )

    if vulnerability_ids is None:
        return ApprovedRemediationPlanResult(
            plan=None,
            planned=False,
            status="INVALID_VULNERABILITY_IDS",
        )

    plan = ApprovedRemediationPlan(
        dependency_name=dependency_name,
        current_version=current_version,
        target_version=target_version,
        vulnerability_ids=vulnerability_ids,
        authorized=True,
    )

    return ApprovedRemediationPlanResult(
        plan=plan,
        planned=True,
        status="APPROVED_REMEDIATION_PLAN_CREATED",
    )


def approved_remediation_plan(
    plan_input: ApprovedRemediationPlanInput,
) -> ApprovedRemediationPlanResult:
    return create_approved_remediation_plan(plan_input)
