from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class VersionConstraintCompatibilityResult:
    version: str
    constraint: str
    compatible: bool
    reason: str


@dataclass(frozen=True)
class VersionConstraintCheckInput:
    version: str
    constraint: str


def _parse_version(version: object) -> tuple[int, int, int]:
    if not isinstance(version, str):
        raise TypeError("VERSION_MUST_BE_STRING")

    value = version.strip()

    if not value:
        raise ValueError("VERSION_IS_EMPTY")

    if value.startswith(("v", "V")):
        value = value[1:]

    value = value.split("-", 1)[0].split("+", 1)[0]
    parts = value.split(".")

    if len(parts) != 3:
        raise ValueError("VERSION_MUST_HAVE_MAJOR_MINOR_PATCH")

    if not all(part.isdigit() for part in parts):
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NUMERIC")

    return tuple(int(part) for part in parts)


def _normalize_constraint(constraint: object) -> str:
    if not isinstance(constraint, str):
        raise TypeError("CONSTRAINT_MUST_BE_STRING")

    value = constraint.strip()

    if not value:
        raise ValueError("CONSTRAINT_IS_EMPTY")

    return value


def _compare(
    version: tuple[int, int, int],
    target: tuple[int, int, int],
) -> int:
    if version < target:
        return -1
    if version > target:
        return 1
    return 0


def _check_single(
    version: tuple[int, int, int],
    operator: str,
    target: tuple[int, int, int],
) -> bool:
    comparison = _compare(version, target)

    if operator == "==":
        return comparison == 0
    if operator == "!=":
        return comparison != 0
    if operator == ">":
        return comparison > 0
    if operator == ">=":
        return comparison >= 0
    if operator == "<":
        return comparison < 0
    if operator == "<=":
        return comparison <= 0

    raise ValueError("UNSUPPORTED_CONSTRAINT_OPERATOR")


def _parse_expression(expression: str) -> tuple[str, tuple[int, int, int]]:
    expression = expression.strip()

    operators = (">=", "<=", "!=", "==", ">", "<", "=")

    operator = None
    target_text = None

    for candidate_operator in operators:
        if expression.startswith(candidate_operator):
            operator = candidate_operator
            target_text = expression[len(candidate_operator):].strip()
            break

    if operator is None:
        # A bare version means exact equality.
        #
        # If the expression starts with a non-version operator character,
        # reject it explicitly instead of allowing the version parser to
        # produce a misleading numeric-component error.
        if expression[0] in "~^*|&!<>=()[]{}":
            raise ValueError("UNSUPPORTED_CONSTRAINT_OPERATOR")

        operator = "=="
        target_text = expression

    if operator == "=":
        operator = "=="

    if not target_text:
        raise ValueError("CONSTRAINT_VERSION_IS_EMPTY")

    return operator, _parse_version(target_text)


def _evaluate(
    version: tuple[int, int, int],
    constraint: str,
) -> bool:
    # Support comma and whitespace separated comparator expressions.
    #
    # Examples:
    #   >=1.2.0
    #   >=1.2.0,<2.0.0
    #   >=1.2.0 <2.0.0
    expressions = constraint.replace(",", " ").split()

    if not expressions:
        raise ValueError("CONSTRAINT_IS_EMPTY")

    return all(
        _check_single(
            version,
            operator,
            target,
        )
        for operator, target in (
            _parse_expression(expression)
            for expression in expressions
        )
    )


def check_version_constraint_compatibility(
    version: str,
    constraint: str,
) -> VersionConstraintCompatibilityResult:
    normalized_version = version.strip() if isinstance(version, str) else version
    normalized_constraint = _normalize_constraint(constraint)

    parsed_version = _parse_version(normalized_version)

    compatible = _evaluate(
        parsed_version,
        normalized_constraint,
    )

    reason = (
        "VERSION_SATISFIES_CONSTRAINT"
        if compatible
        else "VERSION_DOES_NOT_SATISFY_CONSTRAINT"
    )

    return VersionConstraintCompatibilityResult(
        version=normalized_version,
        constraint=normalized_constraint,
        compatible=compatible,
        reason=reason,
    )


# Public aliases.
version_constraint_compatibility_check = (
    check_version_constraint_compatibility
)
is_version_constraint_compatible = (
    check_version_constraint_compatibility
)


__all__ = [
    "VersionConstraintCompatibilityResult",
    "VersionConstraintCheckInput",
    "check_version_constraint_compatibility",
    "version_constraint_compatibility_check",
    "is_version_constraint_compatible",
]
