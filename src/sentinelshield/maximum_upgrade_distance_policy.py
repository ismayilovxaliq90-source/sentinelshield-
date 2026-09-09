from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class MaximumUpgradeDistancePolicyInput:
    policy: RemediationPolicy
    current_version: str
    candidate_version: str


@dataclass(frozen=True)
class MaximumUpgradeDistancePolicyResult:
    allowed: bool
    current_version: str
    candidate_version: str
    upgrade_distance: int
    maximum_upgrade_distance: int | None
    reason: str


def _version_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(
            f"{field}_MUST_BE_STRING"
        )

    value = value.strip()

    if not value:
        raise ValueError(
            f"{field}_IS_EMPTY"
        )

    return value


def _parse_version(value: str, field: str) -> tuple[int, int, int]:
    normalized = value.strip()

    if normalized.startswith(("v", "V")):
        normalized = normalized[1:]

    # Build metadata / pre-release suffixes do not participate
    # in the major/minor/patch distance calculation.
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


def _upgrade_distance(
    current: tuple[int, int, int],
    candidate: tuple[int, int, int],
) -> int:
    major_delta = candidate[0] - current[0]
    minor_delta = candidate[1] - current[1]
    patch_delta = candidate[2] - current[2]

    # A lexicographic semantic-version distance is represented
    # as a monotonic scalar. Each major step dominates all
    # minor/patch steps.
    return (
        major_delta * 1_000_000
        + minor_delta * 1_000
        + patch_delta
    )


def evaluate_maximum_upgrade_distance_policy(
    request: MaximumUpgradeDistancePolicyInput,
) -> MaximumUpgradeDistancePolicyResult:

    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        MaximumUpgradeDistancePolicyInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_MAXIMUM_UPGRADE_DISTANCE_POLICY_INPUT"
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

    maximum = request.policy.maximum_upgrade_distance

    if maximum is not None:
        if isinstance(maximum, bool):
            raise TypeError(
                "MAXIMUM_UPGRADE_DISTANCE_MUST_BE_INTEGER"
            )

        if not isinstance(maximum, int):
            raise TypeError(
                "MAXIMUM_UPGRADE_DISTANCE_MUST_BE_INTEGER"
            )

        if maximum < 0:
            raise ValueError(
                "MAXIMUM_UPGRADE_DISTANCE_MUST_BE_NONNEGATIVE"
            )

    distance = _upgrade_distance(
        current,
        candidate,
    )

    # Candidate is not an upgrade.
    if candidate <= current:
        return MaximumUpgradeDistancePolicyResult(
            allowed=False,
            current_version=current_version,
            candidate_version=candidate_version,
            upgrade_distance=distance,
            maximum_upgrade_distance=maximum,
            reason="CANDIDATE_IS_NOT_AN_UPGRADE",
        )

    # No maximum-distance policy configured.
    if maximum is None:
        return MaximumUpgradeDistancePolicyResult(
            allowed=True,
            current_version=current_version,
            candidate_version=candidate_version,
            upgrade_distance=distance,
            maximum_upgrade_distance=None,
            reason="MAXIMUM_UPGRADE_DISTANCE_POLICY_NOT_CONFIGURED",
        )

    if distance > maximum:
        return MaximumUpgradeDistancePolicyResult(
            allowed=False,
            current_version=current_version,
            candidate_version=candidate_version,
            upgrade_distance=distance,
            maximum_upgrade_distance=maximum,
            reason="UPGRADE_DISTANCE_EXCEEDS_MAXIMUM",
        )

    return MaximumUpgradeDistancePolicyResult(
        allowed=True,
        current_version=current_version,
        candidate_version=candidate_version,
        upgrade_distance=distance,
        maximum_upgrade_distance=maximum,
        reason="UPGRADE_DISTANCE_WITHIN_MAXIMUM",
    )


def maximum_upgrade_distance_policy(
    request: MaximumUpgradeDistancePolicyInput,
) -> MaximumUpgradeDistancePolicyResult:
    return evaluate_maximum_upgrade_distance_policy(request)


def check_maximum_upgrade_distance(
    request: MaximumUpgradeDistancePolicyInput,
) -> MaximumUpgradeDistancePolicyResult:
    return evaluate_maximum_upgrade_distance_policy(request)


def is_upgrade_distance_allowed(
    request: MaximumUpgradeDistancePolicyInput,
) -> bool:
    return evaluate_maximum_upgrade_distance_policy(request).allowed


__all__ = [
    "MaximumUpgradeDistancePolicyInput",
    "MaximumUpgradeDistancePolicyResult",
    "evaluate_maximum_upgrade_distance_policy",
    "maximum_upgrade_distance_policy",
    "check_maximum_upgrade_distance",
    "is_upgrade_distance_allowed",
]
