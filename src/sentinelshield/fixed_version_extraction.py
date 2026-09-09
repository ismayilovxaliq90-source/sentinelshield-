from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class FixedVersion:
    package: str
    version: str


@dataclass(frozen=True)
class FixedVersionExtractionResult:
    fixed_versions: tuple[FixedVersion, ...]
    extracted: bool
    status: str


_FIXED_VERSION_FIELDS = (
    "fixed_version",
    "fixedVersion",
    "fixed",
    "patched_version",
    "patchedVersion",
    "patched",
)

_PACKAGE_FIELDS = (
    "package",
    "package_name",
    "name",
)


def _read_field(value: Any, fields: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        for field in fields:
            if field in value:
                return value[field]

    for field in fields:
        try:
            result = getattr(value, field)
        except AttributeError:
            continue

        if result is not None:
            return result

    return None


def _normalize_package(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    return value


def _normalize_versions(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()

    if isinstance(value, str):
        value = (value,)

    elif isinstance(value, bytes):
        return ()

    else:
        try:
            value = tuple(value)
        except TypeError:
            value = (value,)

    normalized: set[str] = set()

    for version in value:
        if not isinstance(version, str):
            continue

        version = version.strip()

        if version:
            normalized.add(version)

    return tuple(sorted(normalized))


def _extract_vulnerability(value: Any) -> tuple[Optional[str], tuple[str, ...]]:
    package = _normalize_package(
        _read_field(value, _PACKAGE_FIELDS)
    )

    fixed_value = _read_field(
        value,
        _FIXED_VERSION_FIELDS,
    )

    versions = _normalize_versions(fixed_value)

    return package, versions


def extract_fixed_versions(
    vulnerabilities: Any,
) -> FixedVersionExtractionResult:
    if vulnerabilities is None:
        return FixedVersionExtractionResult(
            fixed_versions=(),
            extracted=False,
            status="VULNERABILITIES_IS_NONE",
        )

    if isinstance(vulnerabilities, str):
        vulnerabilities = (vulnerabilities,)
    elif isinstance(vulnerabilities, bytes):
        return FixedVersionExtractionResult(
            fixed_versions=(),
            extracted=False,
            status="UNSUPPORTED_VULNERABILITY_COLLECTION",
        )
    else:
        try:
            vulnerabilities = tuple(vulnerabilities)
        except TypeError:
            return FixedVersionExtractionResult(
                fixed_versions=(),
                extracted=False,
                status="UNSUPPORTED_VULNERABILITY_COLLECTION",
            )

    if not vulnerabilities:
        return FixedVersionExtractionResult(
            fixed_versions=(),
            extracted=False,
            status="NO_VULNERABILITIES",
        )

    extracted: set[FixedVersion] = set()

    for vulnerability in vulnerabilities:
        package, versions = _extract_vulnerability(vulnerability)

        if package is None:
            continue

        for version in versions:
            extracted.add(
                FixedVersion(
                    package=package,
                    version=version,
                )
            )

    result = tuple(
        sorted(
            extracted,
            key=lambda item: (
                item.package.casefold(),
                0 if item.package[:1].islower() else 1,
                item.package,
                item.version,
            ),
        )
    )

    if not result:
        return FixedVersionExtractionResult(
            fixed_versions=(),
            extracted=False,
            status="NO_FIXED_VERSIONS",
        )

    return FixedVersionExtractionResult(
        fixed_versions=result,
        extracted=True,
        status="FIXED_VERSIONS_EXTRACTED",
    )


def extract_fixed_version(
    vulnerability: Any,
) -> FixedVersionExtractionResult:
    return extract_fixed_versions((vulnerability,))
