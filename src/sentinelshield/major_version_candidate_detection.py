from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Tuple


@dataclass(frozen=True)
class MajorVersionCandidate:
    version: str
    original_index: int
    major: int
    minor: int
    patch: int
    major_distance: int
    is_major_upgrade: bool = True


@dataclass(frozen=True)
class MajorVersionCandidateDetectionResult:
    package_name: Optional[str]
    current_version: str
    candidates: Tuple[MajorVersionCandidate, ...]
    total: int


@dataclass(frozen=True)
class MajorVersionDetectionInput:
    package_name: Optional[str]
    current_version: str
    candidate_versions: Iterable[str]


def _parse_version(version: object) -> tuple[int, int, int]:
    if not isinstance(version, str):
        raise TypeError("VERSION_MUST_BE_STRING")

    value = version.strip()

    if not value:
        raise ValueError("VERSION_IS_EMPTY")

    if value.startswith(("v", "V")):
        value = value[1:]

    # Compare semantic numeric core only.
    value = value.split("-", 1)[0].split("+", 1)[0]
    parts = value.split(".")

    if len(parts) != 3:
        raise ValueError("VERSION_MUST_HAVE_MAJOR_MINOR_PATCH")

    if not all(part.isdigit() for part in parts):
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NUMERIC")

    major, minor, patch = (int(part) for part in parts)

    return major, minor, patch


def _normalize_input(
    package_name: Optional[str],
    current_version: str,
    candidate_versions: Iterable[str],
) -> MajorVersionDetectionInput:
    if package_name is not None and not isinstance(package_name, str):
        raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")

    if isinstance(current_version, bool) or not isinstance(current_version, str):
        raise TypeError("CURRENT_VERSION_MUST_BE_STRING")

    if candidate_versions is None:
        raise TypeError("CANDIDATE_VERSIONS_MUST_NOT_BE_NONE")

    if isinstance(candidate_versions, (str, bytes, bytearray)):
        raise TypeError("CANDIDATE_VERSIONS_MUST_BE_ITERABLE_OF_STRINGS")

    try:
        iterator = iter(candidate_versions)
    except TypeError as exc:
        raise TypeError(
            "CANDIDATE_VERSIONS_MUST_BE_ITERABLE_OF_STRINGS"
        ) from exc

    _parse_version(current_version)

    return MajorVersionDetectionInput(
        package_name=package_name.strip() if package_name is not None else None,
        current_version=current_version.strip(),
        candidate_versions=iterator,
    )


def detect_major_version_candidates(
    package_name: Optional[str],
    current_version: str,
    candidate_versions: Iterable[str],
) -> MajorVersionCandidateDetectionResult:
    """
    Detect candidates representing major-version upgrades.

    A candidate is a major upgrade when:
      - candidate version is newer than current version;
      - candidate major is strictly greater than current major.

    Minor and patch upgrades are excluded.
    """
    normalized = _normalize_input(
        package_name,
        current_version,
        candidate_versions,
    )

    current_major, current_minor, current_patch = _parse_version(
        normalized.current_version
    )
    current_tuple = (
        current_major,
        current_minor,
        current_patch,
    )

    candidates: list[MajorVersionCandidate] = []
    seen: set[str] = set()

    for index, raw_version in enumerate(normalized.candidate_versions):
        if not isinstance(raw_version, str):
            raise TypeError("VERSION_MUST_BE_STRING")

        version = raw_version.strip()

        if version in seen:
            continue

        seen.add(version)

        major, minor, patch = _parse_version(version)
        candidate_tuple = (major, minor, patch)

        # Must be an actual upgrade.
        if candidate_tuple <= current_tuple:
            continue

        # Major upgrade requires a strictly higher major version.
        if major <= current_major:
            continue

        candidates.append(
            MajorVersionCandidate(
                version=version,
                original_index=index,
                major=major,
                minor=minor,
                patch=patch,
                major_distance=major - current_major,
            )
        )

    # Deterministic ordering:
    # closest major first, then minor, patch, original position.
    candidates.sort(
        key=lambda item: (
            item.major_distance,
            item.minor,
            item.patch,
            item.original_index,
        )
    )

    return MajorVersionCandidateDetectionResult(
        package_name=normalized.package_name,
        current_version=normalized.current_version,
        candidates=tuple(candidates),
        total=len(candidates),
    )


# Public API aliases.
major_version_candidate_detection = detect_major_version_candidates
detect_major_version_candidate = detect_major_version_candidates


__all__ = [
    "MajorVersionCandidate",
    "MajorVersionCandidateDetectionResult",
    "MajorVersionDetectionInput",
    "detect_major_version_candidates",
    "detect_major_version_candidate",
    "major_version_candidate_detection",
]
