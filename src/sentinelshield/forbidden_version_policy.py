from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class ForbiddenVersionPolicyInput:
    policy: RemediationPolicy
    candidate_version: str


@dataclass(frozen=True)
class ForbiddenVersionPolicyResult:
    allowed: bool
    candidate_version: str
    forbidden_versions: tuple[str, ...]
    reason: str


def _normalize_candidate_version(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("CANDIDATE_VERSION_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError("CANDIDATE_VERSION_IS_EMPTY")

    return value


def _normalize_forbidden_versions(
    versions: object,
) -> tuple[str, ...]:
    if not isinstance(versions, (tuple, list)):
        raise TypeError(
            "FORBIDDEN_VERSIONS_MUST_BE_SEQUENCE"
        )

    normalized: list[str] = []

    for version in versions:
        if not isinstance(version, str):
            raise TypeError(
                "FORBIDDEN_VERSIONS_ITEM_MUST_BE_STRING"
            )

        value = version.strip()

        if not value:
            raise ValueError(
                "FORBIDDEN_VERSIONS_ITEM_IS_EMPTY"
            )

        normalized.append(value)

    return tuple(dict.fromkeys(normalized))


def evaluate_forbidden_version_policy(
    request: ForbiddenVersionPolicyInput,
) -> ForbiddenVersionPolicyResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        ForbiddenVersionPolicyInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_FORBIDDEN_VERSION_POLICY_INPUT"
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

    candidate_version = _normalize_candidate_version(
        request.candidate_version
    )

    forbidden_versions = _normalize_forbidden_versions(
        request.policy.forbidden_versions
    )

    if not forbidden_versions:
        return ForbiddenVersionPolicyResult(
            allowed=True,
            candidate_version=candidate_version,
            forbidden_versions=forbidden_versions,
            reason="FORBIDDEN_VERSION_POLICY_NOT_CONFIGURED",
        )

    if candidate_version in forbidden_versions:
        return ForbiddenVersionPolicyResult(
            allowed=False,
            candidate_version=candidate_version,
            forbidden_versions=forbidden_versions,
            reason="CANDIDATE_VERSION_FORBIDDEN",
        )

    return ForbiddenVersionPolicyResult(
        allowed=True,
        candidate_version=candidate_version,
        forbidden_versions=forbidden_versions,
        reason="CANDIDATE_VERSION_NOT_FORBIDDEN",
    )


def forbidden_version_policy(
    request: ForbiddenVersionPolicyInput,
) -> ForbiddenVersionPolicyResult:
    return evaluate_forbidden_version_policy(request)


def check_forbidden_version(
    request: ForbiddenVersionPolicyInput,
) -> ForbiddenVersionPolicyResult:
    return evaluate_forbidden_version_policy(request)


def is_version_forbidden(
    request: ForbiddenVersionPolicyInput,
) -> bool:
    return not evaluate_forbidden_version_policy(request).allowed


__all__ = [
    "ForbiddenVersionPolicyInput",
    "ForbiddenVersionPolicyResult",
    "evaluate_forbidden_version_policy",
    "forbidden_version_policy",
    "check_forbidden_version",
    "is_version_forbidden",
]
