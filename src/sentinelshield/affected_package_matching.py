from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class AffectedPackageMatch:
    dependency_name: str
    vulnerability_package: str
    matched: bool


@dataclass(frozen=True)
class AffectedPackageMatchingResult:
    matches: tuple[AffectedPackageMatch, ...]
    matched: bool
    status: str


def _normalize_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip().lower()

    if not value:
        return None

    # Python / package ecosystem canonicalization.
    return value.replace("_", "-").replace(".", "-")


def _extract_dependency_name(item: Any) -> Any:
    if isinstance(item, str):
        return item

    if isinstance(item, dict):
        for key in ("name", "package", "package_name"):
            if key in item:
                return item[key]
        return None

    for attribute in ("name", "package", "package_name"):
        if hasattr(item, attribute):
            return getattr(item, attribute)

    return None


def _extract_vulnerability_package(item: Any) -> Any:
    if isinstance(item, str):
        return item

    if isinstance(item, dict):
        for key in ("package", "package_name", "name"):
            if key in item:
                return item[key]
        return None

    for attribute in ("package", "package_name", "name"):
        if hasattr(item, attribute):
            return getattr(item, attribute)

    return None


def match_affected_packages(
    dependencies: Iterable[Any] | Any,
    vulnerabilities: Iterable[Any] | Any,
) -> AffectedPackageMatchingResult:

    if dependencies is None:
        return AffectedPackageMatchingResult(
            matches=(),
            matched=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if vulnerabilities is None:
        return AffectedPackageMatchingResult(
            matches=(),
            matched=False,
            status="VULNERABILITIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        dependencies = (dependencies,)

    if isinstance(vulnerabilities, (str, bytes)):
        vulnerabilities = (vulnerabilities,)

    try:
        dependency_items = tuple(dependencies)
    except TypeError:
        return AffectedPackageMatchingResult(
            matches=(),
            matched=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        vulnerability_items = tuple(vulnerabilities)
    except TypeError:
        return AffectedPackageMatchingResult(
            matches=(),
            matched=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )

    dependency_names: list[str] = []

    for item in dependency_items:
        name = _normalize_name(_extract_dependency_name(item))
        if name is None:
            return AffectedPackageMatchingResult(
                matches=(),
                matched=False,
                status="INVALID_DEPENDENCY_NAME",
            )
        dependency_names.append(name)

    vulnerability_names: list[str] = []

    for item in vulnerability_items:
        name = _normalize_name(
            _extract_vulnerability_package(item)
        )
        if name is None:
            return AffectedPackageMatchingResult(
                matches=(),
                matched=False,
                status="INVALID_VULNERABILITY_PACKAGE",
            )
        vulnerability_names.append(name)

    matches: list[AffectedPackageMatch] = []

    for dependency_name in dependency_names:
        for vulnerability_name in vulnerability_names:
            if dependency_name == vulnerability_name:
                matches.append(
                    AffectedPackageMatch(
                        dependency_name=dependency_name,
                        vulnerability_package=vulnerability_name,
                        matched=True,
                    )
                )

    matches.sort(
        key=lambda item: (
            item.dependency_name,
            item.vulnerability_package,
        )
    )

    return AffectedPackageMatchingResult(
        matches=tuple(matches),
        matched=bool(matches),
        status=(
            "AFFECTED_PACKAGES_MATCHED"
            if matches
            else "NO_AFFECTED_PACKAGES"
        ),
    )


def match_affected_package(
    dependency: Any,
    vulnerability: Any,
) -> AffectedPackageMatchingResult:
    return match_affected_packages(
        (dependency,),
        (vulnerability,),
    )
