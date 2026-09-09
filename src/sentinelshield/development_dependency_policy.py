from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class DevelopmentDependencyPolicyInput:
    policy: RemediationPolicy
    is_development_dependency: bool


@dataclass(frozen=True)
class DevelopmentDependencyPolicyResult:
    allowed: bool
    is_development_dependency: bool
    allow_development_dependencies: bool
    reason: str


def evaluate_development_dependency_policy(
    request: DevelopmentDependencyPolicyInput,
) -> DevelopmentDependencyPolicyResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        DevelopmentDependencyPolicyInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_DEVELOPMENT_DEPENDENCY_POLICY_INPUT"
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

    if not isinstance(
        request.is_development_dependency,
        bool,
    ):
        raise TypeError(
            "IS_DEVELOPMENT_DEPENDENCY_MUST_BE_BOOLEAN"
        )

    allow_development = (
        request.policy.allow_development_dependencies
    )

    if not isinstance(allow_development, bool):
        raise TypeError(
            "ALLOW_DEVELOPMENT_DEPENDENCIES_MUST_BE_BOOLEAN"
        )

    # This policy only governs development dependencies.
    # Production dependencies pass through this gate.
    if not request.is_development_dependency:
        return DevelopmentDependencyPolicyResult(
            allowed=True,
            is_development_dependency=False,
            allow_development_dependencies=allow_development,
            reason="NOT_A_DEVELOPMENT_DEPENDENCY",
        )

    if allow_development:
        return DevelopmentDependencyPolicyResult(
            allowed=True,
            is_development_dependency=True,
            allow_development_dependencies=True,
            reason="DEVELOPMENT_DEPENDENCY_ALLOWED",
        )

    return DevelopmentDependencyPolicyResult(
        allowed=False,
        is_development_dependency=True,
        allow_development_dependencies=False,
        reason="DEVELOPMENT_DEPENDENCY_FORBIDDEN",
    )


def development_dependency_policy(
    request: DevelopmentDependencyPolicyInput,
) -> DevelopmentDependencyPolicyResult:
    return evaluate_development_dependency_policy(request)


def check_development_dependency(
    request: DevelopmentDependencyPolicyInput,
) -> DevelopmentDependencyPolicyResult:
    return evaluate_development_dependency_policy(request)


def is_development_dependency_allowed(
    request: DevelopmentDependencyPolicyInput,
) -> bool:
    return evaluate_development_dependency_policy(request).allowed


__all__ = [
    "DevelopmentDependencyPolicyInput",
    "DevelopmentDependencyPolicyResult",
    "evaluate_development_dependency_policy",
    "development_dependency_policy",
    "check_development_dependency",
    "is_development_dependency_allowed",
]
