from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class MajorUpgradePolicyInput:
    policy: RemediationPolicy
    current_version: str
    candidate_version: str


@dataclass(frozen=True)
class MajorUpgradePolicyResult:
    allowed: bool
    current_version: str
    candidate_version: str
    is_upgrade: bool
    is_major_upgrade: bool
    reason: str


def _version_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field}_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError(f"{field}_IS_EMPTY")

    return value


def _parse_version(
    value: str,
    field: str,
) -> tuple[int, int, int]:
    normalized = value.strip()

    if normalized.startswith(("v", "V")):
        normalized = normalized[1:]

    normalized = normalized.split("+", 1)[0]
    normalized = normalized.split("-", 1)[0]

    parts = normalized.split(".")

    if not 1 <= len(parts) <= 3:
        raise ValueError(
            f"{field}_MUST_HAVE_1_TO_3_COMPONENTS"
        )

    numbers: list[int] = []

    for part in parts:
        if not part.isdigit():
            raise ValueError(
                f"{field}_COMPONENTS_MUST_BE_NUMERIC"
            )

        numbers.append(int(part))

    while len(numbers) < 3:
        numbers.append(0)

    return tuple(numbers)  # type: ignore[return-value]


def evaluate_major_upgrade_policy(
    request: MajorUpgradePolicyInput,
) -> MajorUpgradePolicyResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        MajorUpgradePolicyInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_MAJOR_UPGRADE_POLICY_INPUT"
        )

    if request.policy is None:
        raise TypeError("POLICY_IS_NONE")

    if not isinstance(
        request.policy,
        RemediationPolicy,
    ):
        raise TypeError(
            "POLICY_MUST_BE_REMEDIATION_POLICY"
        )

    current_version = _version_text(
        request.current_version,
        "CURRENT_VERSION",
    )

    candidate_version = _version_text(
        request.candidate_version,
        "CANDIDATE_VERSION",
    )

    current = _parse_version(
        current_version,
        "CURRENT_VERSION",
    )

    candidate = _parse_version(
        candidate_version,
        "CANDIDATE_VERSION",
    )

    is_upgrade = candidate > current
    is_major_upgrade = (
        is_upgrade
        and candidate[0] > current[0]
    )

    if not is_upgrade:
        return MajorUpgradePolicyResult(
            allowed=False,
            current_version=current_version,
            candidate_version=candidate_version,
            is_upgrade=False,
            is_major_upgrade=False,
            reason="CANDIDATE_IS_NOT_AN_UPGRADE",
        )

    if not is_major_upgrade:
        return MajorUpgradePolicyResult(
            allowed=True,
            current_version=current_version,
            candidate_version=candidate_version,
            is_upgrade=True,
            is_major_upgrade=False,
            reason="NON_MAJOR_UPGRADE_ALLOWED",
        )

    if request.policy.allow_major_upgrades:
        return MajorUpgradePolicyResult(
            allowed=True,
            current_version=current_version,
            candidate_version=candidate_version,
            is_upgrade=True,
            is_major_upgrade=True,
            reason="MAJOR_UPGRADE_ALLOWED",
        )

    return MajorUpgradePolicyResult(
        allowed=False,
        current_version=current_version,
        candidate_version=candidate_version,
        is_upgrade=True,
        is_major_upgrade=True,
        reason="MAJOR_UPGRADE_FORBIDDEN",
    )


def major_upgrade_policy(
    request: MajorUpgradePolicyInput,
) -> MajorUpgradePolicyResult:
    return evaluate_major_upgrade_policy(request)


def check_major_upgrade(
    request: MajorUpgradePolicyInput,
) -> MajorUpgradePolicyResult:
    return evaluate_major_upgrade_policy(request)


def is_major_upgrade_allowed(
    request: MajorUpgradePolicyInput,
) -> bool:
    return evaluate_major_upgrade_policy(request).allowed


__all__ = [
    "MajorUpgradePolicyInput",
    "MajorUpgradePolicyResult",
    "evaluate_major_upgrade_policy",
    "major_upgrade_policy",
    "check_major_upgrade",
    "is_major_upgrade_allowed",
]
