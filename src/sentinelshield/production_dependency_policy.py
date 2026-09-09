from __future__ import annotations

from dataclasses import dataclass

from .remediation_policy_loading import RemediationPolicy


@dataclass(frozen=True)
class ProductionDependencyPolicyInput:
    policy: RemediationPolicy
    is_production_dependency: bool


@dataclass(frozen=True)
class ProductionDependencyPolicyResult:
    allowed: bool
    is_production_dependency: bool
    allow_production_dependencies: bool
    reason: str


def evaluate_production_dependency_policy(
    request: ProductionDependencyPolicyInput,
) -> ProductionDependencyPolicyResult:
    if request is None:
        raise TypeError("INPUT_IS_NONE")

    if not isinstance(
        request,
        ProductionDependencyPolicyInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_PRODUCTION_DEPENDENCY_POLICY_INPUT"
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
        request.is_production_dependency,
        bool,
    ):
        raise TypeError(
            "IS_PRODUCTION_DEPENDENCY_MUST_BE_BOOLEAN"
        )

    allow_production = request.policy.allow_production_dependencies

    if not isinstance(allow_production, bool):
        raise TypeError(
            "ALLOW_PRODUCTION_DEPENDENCIES_MUST_BE_BOOLEAN"
        )

    # This policy only governs production dependencies.
    # Non-production dependencies pass through this gate.
    if not request.is_production_dependency:
        return ProductionDependencyPolicyResult(
            allowed=True,
            is_production_dependency=False,
            allow_production_dependencies=allow_production,
            reason="NOT_A_PRODUCTION_DEPENDENCY",
        )

    if allow_production:
        return ProductionDependencyPolicyResult(
            allowed=True,
            is_production_dependency=True,
            allow_production_dependencies=True,
            reason="PRODUCTION_DEPENDENCY_ALLOWED",
        )

    return ProductionDependencyPolicyResult(
        allowed=False,
        is_production_dependency=True,
        allow_production_dependencies=False,
        reason="PRODUCTION_DEPENDENCY_FORBIDDEN",
    )


def production_dependency_policy(
    request: ProductionDependencyPolicyInput,
) -> ProductionDependencyPolicyResult:
    return evaluate_production_dependency_policy(request)


def check_production_dependency(
    request: ProductionDependencyPolicyInput,
) -> ProductionDependencyPolicyResult:
    return evaluate_production_dependency_policy(request)


def is_production_dependency_allowed(
    request: ProductionDependencyPolicyInput,
) -> bool:
    return evaluate_production_dependency_policy(request).allowed


__all__ = [
    "ProductionDependencyPolicyInput",
    "ProductionDependencyPolicyResult",
    "evaluate_production_dependency_policy",
    "production_dependency_policy",
    "check_production_dependency",
    "is_production_dependency_allowed",
]
