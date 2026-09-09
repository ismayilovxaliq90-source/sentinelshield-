from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class NormalizedPackageName:
    original_name: str
    normalized_name: str
    source: Optional[str] = None


@dataclass(frozen=True)
class PackageNameNormalizationResult:
    packages: tuple[NormalizedPackageName, ...]
    normalized: bool
    status: str


def _normalize_package_name(value: Any) -> tuple[Optional[str], str]:
    if not isinstance(value, str):
        return None, "INVALID_PACKAGE_NAME"

    name = value.strip()

    if not name:
        return None, "INVALID_PACKAGE_NAME"

    # Preserve scoped package semantics while normalizing
    # surrounding whitespace and redundant internal spacing.
    if name.startswith("@"):
        parts = name.split("/", 1)

        if len(parts) != 2:
            return None, "INVALID_PACKAGE_NAME"

        scope, package = parts

        if not scope[1:] or not package:
            return None, "INVALID_PACKAGE_NAME"

        if " " in scope or " " in package:
            return None, "INVALID_PACKAGE_NAME"

        normalized = (
            "@"
            + scope[1:].strip().lower()
            + "/"
            + package.strip().lower()
        )
    else:
        if "/" in name:
            return None, "INVALID_PACKAGE_NAME"

        if any(character.isspace() for character in name):
            return None, "INVALID_PACKAGE_NAME"

        normalized = name.lower()

    return normalized, "VALID"


def normalize_package_names(
    packages: Iterable[Any],
) -> PackageNameNormalizationResult:

    if packages is None:
        return PackageNameNormalizationResult(
            packages=(),
            normalized=False,
            status="PACKAGES_IS_NONE",
        )

    if isinstance(packages, (str, bytes)):
        return PackageNameNormalizationResult(
            packages=(),
            normalized=False,
            status="UNSUPPORTED_PACKAGE_COLLECTION",
        )

    try:
        items = tuple(packages)
    except TypeError:
        return PackageNameNormalizationResult(
            packages=(),
            normalized=False,
            status="UNSUPPORTED_PACKAGE_COLLECTION",
        )

    result: list[NormalizedPackageName] = []

    for package in items:
        if not hasattr(package, "name"):
            return PackageNameNormalizationResult(
                packages=(),
                normalized=False,
                status="INVALID_PACKAGE",
            )

        original_name = getattr(package, "name")

        normalized_name, status = _normalize_package_name(
            original_name
        )

        if normalized_name is None:
            return PackageNameNormalizationResult(
                packages=(),
                normalized=False,
                status=status,
            )

        source = getattr(package, "source", None)

        if source is not None:
            if not isinstance(source, str):
                return PackageNameNormalizationResult(
                    packages=(),
                    normalized=False,
                    status="INVALID_PACKAGE_SOURCE",
                )

            source = source.strip() or None

        result.append(
            NormalizedPackageName(
                original_name=original_name,
                normalized_name=normalized_name,
                source=source,
            )
        )

    return PackageNameNormalizationResult(
        packages=tuple(result),
        normalized=True,
        status="NORMALIZED",
    )


def normalize_package_name(
    package: Any,
) -> PackageNameNormalizationResult:
    return normalize_package_names([package])
