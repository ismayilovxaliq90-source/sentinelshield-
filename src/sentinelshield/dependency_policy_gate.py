from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DependencyPolicyGateInput:
    policy: Any
    requested_dependency_policy: Any


@dataclass(frozen=True)
class DependencyPolicyGateResult:
    allowed: bool
    status: str


_VALID_POLICIES = {
    "direct",
    "transitive",
    "development",
    "optional",
    "peer",
    "production",
}


def _normalize_policy(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    aliases = {
        "direct": "direct",
        "direct-only": "direct",
        "direct_only": "direct",

        "transitive": "transitive",
        "transitive-only": "transitive",
        "transitive_only": "transitive",

        "development": "development",
        "dev": "development",
        "development-only": "development",
        "development_only": "development",

        "optional": "optional",
        "optional-only": "optional",
        "optional_only": "optional",

        "peer": "peer",
        "peer-only": "peer",
        "peer_only": "peer",

        "production": "production",
        "prod": "production",
        "production-only": "production",
        "production_only": "production",
    }

    return aliases.get(normalized)


def _extract_policy(value: Any) -> Any:
    if isinstance(value, dict):
        for key in (
            "dependency_policy",
            "policy",
            "dependencyPolicy",
        ):
            if key in value:
                return value[key]
        return None

    for attribute in (
        "dependency_policy",
        "policy",
        "dependencyPolicy",
    ):
        try:
            return getattr(value, attribute)
        except AttributeError:
            continue

    return value


def evaluate_dependency_policy_gate(
    gate_input: DependencyPolicyGateInput,
) -> DependencyPolicyGateResult:
    if not isinstance(gate_input, DependencyPolicyGateInput):
        return DependencyPolicyGateResult(
            allowed=False,
            status="INVALID_GATE_INPUT",
        )

    configured_raw = _extract_policy(gate_input.policy)
    requested_raw = gate_input.requested_dependency_policy

    if configured_raw is None:
        return DependencyPolicyGateResult(
            allowed=False,
            status="POLICY_IS_MISSING",
        )

    configured = _normalize_policy(configured_raw)

    if configured is None:
        return DependencyPolicyGateResult(
            allowed=False,
            status="INVALID_POLICY",
        )

    requested = _normalize_policy(requested_raw)

    if requested is None:
        return DependencyPolicyGateResult(
            allowed=False,
            status="INVALID_REQUESTED_DEPENDENCY_POLICY",
        )

    if configured != requested:
        return DependencyPolicyGateResult(
            allowed=False,
            status="DEPENDENCY_POLICY_MISMATCH",
        )

    return DependencyPolicyGateResult(
        allowed=True,
        status="DEPENDENCY_POLICY_ALLOWED",
    )


def dependency_policy_gate(
    gate_input: DependencyPolicyGateInput,
) -> DependencyPolicyGateResult:
    return evaluate_dependency_policy_gate(gate_input)
