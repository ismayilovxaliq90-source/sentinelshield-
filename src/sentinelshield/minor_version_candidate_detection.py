from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Tuple


@dataclass(frozen=True)
class MinorVersionCandidate:
    version: str
    original_index: int
    major: int
    minor: int
    patch: int
    minor_distance: int
    is_minor_upgrade: bool = True


@dataclass(frozen=True)
class MinorVersionCandidateDetectionResult:
    package_name: Optional[str]
    current_version: str
    candidates: Tuple[MinorVersionCandidate, ...]
    total: int


@dataclass(frozen=True)
class MinorVersionDetectionInput:
    package_name: Optional[str]
    current_version: str
    fixed_versions: Iterable[str]


def _parse_version(version: object) -> tuple[int, int, int]:
    if not isinstance(version, str):
        raise TypeError("VERSION_MUST_BE_STRING")

    value = version.strip()

    if not value:
        raise ValueError("VERSION_IS_EMPTY")

    if value.startswith(("v", "V")):
        value = value[1:]

    # Remove prerelease/build suffixes for numeric semantic-core comparison.
    numeric_part = value.split("-", 1)[0].split("+", 1)[0]
    parts = numeric_part.split(".")

    if len(parts) != 3:
        raise ValueError("VERSION_MUST_HAVE_MAJOR_MINOR_PATCH")

    if not all(part.isdigit() for part in parts):
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NUMERIC")

    major, minor, patch = (int(part) for part in parts)

    if major < 0 or minor < 0 or patch < 0:
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NON_NEGATIVE")

    return major, minor, patch


def _normalize_input(
    package_name: Optional[str],
    current_version: str,
    fixed_versions: Iterable[str],
) -> MinorVersionDetectionInput:
    if package_name is not None and not isinstance(package_name, str):
        raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")

    if isinstance(current_version, bool) or not isinstance(current_version, str):
        raise TypeError("CURRENT_VERSION_MUST_BE_STRING")

    if fixed_versions is None:
        raise TypeError("FIXED_VERSIONS_MUST_NOT_BE_NONE")

    if isinstance(fixed_versions, (str, bytes, bytearray)):
        raise TypeError("FIXED_VERSIONS_MUST_BE_ITERABLE_OF_STRINGS")

    # Validate the current version before consuming candidates.
    _parse_version(current_version)

    try:
        iterator = iter(fixed_versions)
    except TypeError as exc:
        raise TypeError(
            "FIXED_VERSIONS_MUST_BE_ITERABLE_OF_STRINGS"
        ) from exc

    return MinorVersionDetectionInput(
        package_name=package_name.strip() if package_name is not None else None,
        current_version=current_version.strip(),
        fixed_versions=iterator,
    )


def detect_minor_version_candidates(
    package_name: Optional[str],
    current_version: str,
    fixed_versions: Iterable[str],
) -> MinorVersionCandidateDetectionResult:
    """
    Detect fixed versions that represent minor upgrades.

    A candidate is a minor upgrade when:
      - candidate major == current major
      - candidate minor > current minor

    Therefore:
      - patch-only upgrades are excluded
      - major upgrades are excluded
      - same-version candidates are excluded
      - older versions are excluded
    """
    normalized = _normalize_input(
        package_name,
        current_version,
        fixed_versions,
    )

    current_major, current_minor, current_patch = _parse_version(
        normalized.current_version
    )

    candidates: list[MinorVersionCandidate] = []
    seen: set[str] = set()

    for index, raw_version in enumerate(normalized.fixed_versions):
        major, minor, patch = _parse_version(raw_version)
        version = raw_version.strip()

        if version in seen:
            continue

        seen.add(version)

        # Minor upgrade:
        # same major + strictly higher minor.
        if major != current_major:
            continue

        if minor <= current_minor:
            continue

        candidates.append(
            MinorVersionCandidate(
                version=version,
                original_index=index,
                major=major,
                minor=minor,
                patch=patch,
                minor_distance=minor - current_minor,
            )
        )

    # Deterministic ordering:
    # 1. closest minor upgrade
    # 2. lower patch
    # 3. original input position
    candidates.sort(
        key=lambda item: (
            item.minor_distance,
            item.patch,
            item.original_index,
        )
    )

    return MinorVersionCandidateDetectionResult(
        package_name=normalized.package_name,
        current_version=normalized.current_version,
        candidates=tuple(candidates),
        total=len(candidates),
    )


# Public alias required by the task API.
minor_version_candidate_detection = detect_minor_version_candidates


__all__ = [
    "MinorVersionCandidate",
    "MinorVersionCandidateDetectionResult",
    "MinorVersionDetectionInput",
    "detect_minor_version_candidates",
    "minor_version_candidate_detection",
]
