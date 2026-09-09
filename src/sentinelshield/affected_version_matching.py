from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
import re


@dataclass(frozen=True)
class AffectedVersionMatch:
    dependency_name: str
    dependency_version: str
    affected_constraint: str
    affected: bool


@dataclass(frozen=True)
class AffectedVersionMatchingResult:
    matches: tuple[AffectedVersionMatch, ...]
    matched: bool
    status: str


_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$")


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        return None

    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
    )


def _normalize_version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    return value


def _extract_dependency(item: Any) -> tuple[Any, Any]:
    if isinstance(item, dict):
        return (
            item.get("name", item.get("package", item.get("package_name"))),
            item.get("version"),
        )

    if isinstance(item, (tuple, list)) and len(item) >= 2:
        return item[0], item[1]

    name = None
    version = None

    for attribute in ("name", "package", "package_name"):
        if hasattr(item, attribute):
            name = getattr(item, attribute)
            break

    if hasattr(item, "version"):
        version = getattr(item, "version")

    return name, version


def _extract_vulnerability(item: Any) -> tuple[Any, Any]:
    if isinstance(item, dict):
        return (
            item.get("package", item.get("package_name", item.get("name"))),
            item.get(
                "affected_versions",
                item.get(
                    "affected_version",
                    item.get(
                        "version_constraint",
                        item.get("constraint"),
                    ),
                ),
            ),
        )

    if isinstance(item, (tuple, list)) and len(item) >= 2:
        return item[0], item[1]

    name = None
    constraint = None

    for attribute in ("package", "package_name", "name"):
        if hasattr(item, attribute):
            name = getattr(item, attribute)
            break

    for attribute in (
        "affected_versions",
        "affected_version",
        "version_constraint",
        "constraint",
    ):
        if hasattr(item, attribute):
            constraint = getattr(item, attribute)
            break

    return name, constraint


def _normalize_package(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip().lower()

    if not value:
        return None

    return value.replace("_", "-").replace(".", "-")


def _compare(version: tuple[int, int, int], target: tuple[int, int, int]) -> int:
    if version < target:
        return -1
    if version > target:
        return 1
    return 0


def _matches_constraint(version: str, constraint: str) -> bool:
    parsed_version = _version_tuple(version)
    if parsed_version is None:
        return False

    constraint = constraint.strip()

    if not constraint:
        return False

    if constraint in {"*", "x", "X"}:
        return True

    # Handle comma-separated AND constraints.
    if "," in constraint:
        parts = [part.strip() for part in constraint.split(",")]
        return all(
            _matches_constraint(version, part)
            for part in parts
        )

    # Handle OR constraints.
    if "||" in constraint:
        return any(
            _matches_constraint(version, part.strip())
            for part in constraint.split("||")
        )

    operators = (">=", "<=", "==", "!=", ">", "<", "^", "~", "~=")

    operator = ""
    value = constraint

    for candidate in operators:
        if constraint.startswith(candidate):
            operator = candidate
            value = constraint[len(candidate):].strip()
            break

    value = value.strip()

    # Wildcard forms such as 1.x, 1.2.x.
    wildcard_parts = value.split(".")
    if any(part.lower() in {"x", "*"} for part in wildcard_parts):
        version_parts = value.split(".")
        for index, part in enumerate(version_parts):
            if part.lower() in {"x", "*"}:
                break
            if not part.isdigit():
                return False
            if parsed_version[index] != int(part):
                return False
        return True

    target = _version_tuple(value)
    if target is None:
        return False

    comparison = _compare(parsed_version, target)

    if operator == ">=":
        return comparison >= 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == "<":
        return comparison < 0
    if operator == "==":
        return comparison == 0
    if operator == "!=":
        return comparison != 0

    if operator in {"^"}:
        if target[0] > 0:
            upper = (target[0] + 1, 0, 0)
        elif target[1] > 0:
            upper = (0, target[1] + 1, 0)
        else:
            upper = (0, 0, target[2] + 1)

        return parsed_version >= target and parsed_version < upper

    if operator in {"~", "~="}:
        upper = (target[0], target[1] + 1, 0)
        return parsed_version >= target and parsed_version < upper

    return comparison == 0


def match_affected_versions(
    dependencies: Iterable[Any] | Any,
    vulnerabilities: Iterable[Any] | Any,
) -> AffectedVersionMatchingResult:

    if dependencies is None:
        return AffectedVersionMatchingResult(
            matches=(),
            matched=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if vulnerabilities is None:
        return AffectedVersionMatchingResult(
            matches=(),
            matched=False,
            status="VULNERABILITIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return AffectedVersionMatchingResult(
            matches=(),
            matched=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    if isinstance(vulnerabilities, (str, bytes)):
        return AffectedVersionMatchingResult(
            matches=(),
            matched=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    try:
        dependency_items = tuple(dependencies)
    except TypeError:
        return AffectedVersionMatchingResult(
            matches=(),
            matched=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        vulnerability_items = tuple(vulnerabilities)
    except TypeError:
        return AffectedVersionMatchingResult(
            matches=(),
            matched=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    parsed_dependencies: list[tuple[str, str]] = []

    for item in dependency_items:
        raw_name, raw_version = _extract_dependency(item)
        name = _normalize_package(raw_name)
        version = _normalize_version(raw_version)

        if name is None:
            return AffectedVersionMatchingResult(
                matches=(),
                matched=False,
                status="INVALID_DEPENDENCY_NAME",
            )

        if version is None:
            return AffectedVersionMatchingResult(
                matches=(),
                matched=False,
                status="INVALID_DEPENDENCY_VERSION",
            )

        if _version_tuple(version) is None:
            return AffectedVersionMatchingResult(
                matches=(),
                matched=False,
                status="INVALID_DEPENDENCY_VERSION",
            )

        parsed_dependencies.append((name, version))

    parsed_vulnerabilities: list[tuple[str, str]] = []

    for item in vulnerability_items:
        raw_name, raw_constraint = _extract_vulnerability(item)
        name = _normalize_package(raw_name)
        constraint = _normalize_version(raw_constraint)

        if name is None:
            return AffectedVersionMatchingResult(
                matches=(),
                matched=False,
                status="INVALID_VULNERABILITY_PACKAGE",
            )

        if constraint is None:
            return AffectedVersionMatchingResult(
                matches=(),
                matched=False,
                status="INVALID_AFFECTED_VERSION_CONSTRAINT",
            )

        parsed_vulnerabilities.append((name, constraint))

    matches: list[AffectedVersionMatch] = []

    for dependency_name, dependency_version in parsed_dependencies:
        for vulnerability_name, constraint in parsed_vulnerabilities:
            if dependency_name != vulnerability_name:
                continue

            if _matches_constraint(
                dependency_version,
                constraint,
            ):
                matches.append(
                    AffectedVersionMatch(
                        dependency_name=dependency_name,
                        dependency_version=dependency_version,
                        affected_constraint=constraint,
                        affected=True,
                    )
                )

    matches.sort(
        key=lambda item: (
            item.dependency_name,
            item.dependency_version,
            item.affected_constraint,
        )
    )

    return AffectedVersionMatchingResult(
        matches=tuple(matches),
        matched=bool(matches),
        status=(
            "AFFECTED_VERSIONS_MATCHED"
            if matches
            else "NO_AFFECTED_VERSIONS"
        ),
    )


def match_affected_version(
    dependency: Any,
    vulnerability: Any,
) -> AffectedVersionMatchingResult:
    return match_affected_versions(
        (dependency,),
        (vulnerability,),
    )
