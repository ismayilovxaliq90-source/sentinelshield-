from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class AllowedVersionPolicyInput:
    policy: RemediationPolicy
    candidate_version: str


@dataclass(frozen=True)
class AllowedVersionPolicyResult:
    allowed: bool
    candidate_version: str
    allowed_versions: tuple[str, ...]
    reason: str


def _version_text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(
            "CANDIDATE_VERSION_MUST_BE_STRING"
        )

    value = value.strip()

    if not value:
        raise ValueError(
            "CANDIDATE_VERSION_IS_EMPTY"
        )

    return value


def _normalize_versions(
    versions: object,
) -> tuple[str, ...]:
    if not isinstance(versions, (tuple, list)):
        raise TypeError(
            "ALLOWED_VERSIONS_MUST_BE_SEQUENCE"
        )

    result: list[str] = []

    for version in versions:
        if not isinstance(version, str):
            raise TypeError(
                "ALLOWED_VERSIONS_ITEM_MUST_BE_STRING"
            )

        normalized = version.strip()

        if not normalized:
            raise ValueError(
                "ALLOWED_VERSIONS_ITEM_IS_EMPTY"
            )

        result.append(normalized)

    return tuple(dict.fromkeys(result))


def evaluate_allowed_version_policy(
    request: AllowedVersionPolicyInput,
) -> AllowedVersionPolicyResult:

    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        AllowedVersionPolicyInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_ALLOWED_VERSION_POLICY_INPUT"
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

    candidate_version = _version_text(
        request.candidate_version
    )

    allowed_versions = _normalize_versions(
        request.policy.allowed_versions
    )

    # An empty allow-list means that this policy does not
    # explicitly restrict versions through allowed_versions.
    if not allowed_versions:
        return AllowedVersionPolicyResult(
            allowed=True,
            candidate_version=candidate_version,
            allowed_versions=allowed_versions,
            reason="ALLOWED_VERSION_POLICY_NOT_CONFIGURED",
        )

    if candidate_version in allowed_versions:
        return AllowedVersionPolicyResult(
            allowed=True,
            candidate_version=candidate_version,
            allowed_versions=allowed_versions,
            reason="CANDIDATE_VERSION_ALLOWED",
        )

    return AllowedVersionPolicyResult(
        allowed=False,
        candidate_version=candidate_version,
        allowed_versions=allowed_versions,
        reason="CANDIDATE_VERSION_NOT_ALLOWED",
    )


def allowed_version_policy(
    request: AllowedVersionPolicyInput,
) -> AllowedVersionPolicyResult:
    return evaluate_allowed_version_policy(request)


def check_allowed_version(
    request: AllowedVersionPolicyInput,
) -> AllowedVersionPolicyResult:
    return evaluate_allowed_version_policy(request)


def is_version_allowed(
    request: AllowedVersionPolicyInput,
) -> bool:
    return evaluate_allowed_version_policy(request).allowed


__all__ = [
    "AllowedVersionPolicyInput",
    "AllowedVersionPolicyResult",
    "evaluate_allowed_version_policy",
    "allowed_version_policy",
    "check_allowed_version",
    "is_version_allowed",
]
