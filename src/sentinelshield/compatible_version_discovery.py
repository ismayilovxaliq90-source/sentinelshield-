from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Tuple


@dataclass(frozen=True)
class CompatibleVersionCandidate:
    version: str
    original_index: int
    major: int
    minor: int
    patch: int
    distance: int
    is_compatible: bool = True


@dataclass(frozen=True)
class CompatibleVersionDiscoveryResult:
    package_name: Optional[str]
    current_version: str
    candidates: Tuple[CompatibleVersionCandidate, ...]
    total: int


@dataclass(frozen=True)
class CompatibleVersionDiscoveryInput:
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

    # Compare the numeric semantic-version core.
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
) -> CompatibleVersionDiscoveryInput:
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

    return CompatibleVersionDiscoveryInput(
        package_name=package_name.strip() if package_name is not None else None,
        current_version=current_version.strip(),
        candidate_versions=iterator,
    )


def discover_compatible_versions(
    package_name: Optional[str],
    current_version: str,
    candidate_versions: Iterable[str],
) -> CompatibleVersionDiscoveryResult:
    """
    Discover compatible upgrade candidates.

    Compatibility policy for this task:
      - candidate must be newer than current version;
      - major version must remain unchanged;
      - therefore patch and minor upgrades are compatible;
      - major-version upgrades are excluded.

    Examples:
      1.2.3 -> 1.2.4  : compatible
      1.2.3 -> 1.3.0  : compatible
      1.2.3 -> 2.0.0  : incompatible
      1.2.3 -> 1.2.3  : not an upgrade
      1.2.3 -> 1.1.9  : not an upgrade
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

    candidates: list[CompatibleVersionCandidate] = []
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

        # Only newer versions can be remediation candidates.
        if candidate_tuple <= current_tuple:
            continue

        # Compatible means no major-version change.
        if major != current_major:
            continue

        distance = (
            (minor - current_minor) * 1000000
            + (patch - current_patch)
        )

        candidates.append(
            CompatibleVersionCandidate(
                version=version,
                original_index=index,
                major=major,
                minor=minor,
                patch=patch,
                distance=distance,
            )
        )

    # Closest compatible upgrade first.
    candidates.sort(
        key=lambda item: (
            item.distance,
            item.major,
            item.minor,
            item.patch,
            item.original_index,
        )
    )

    return CompatibleVersionDiscoveryResult(
        package_name=normalized.package_name,
        current_version=normalized.current_version,
        candidates=tuple(candidates),
        total=len(candidates),
    )


# Public API aliases.
compatible_version_discovery = discover_compatible_versions
discover_compatible_version_candidates = discover_compatible_versions


__all__ = [
    "CompatibleVersionCandidate",
    "CompatibleVersionDiscoveryResult",
    "CompatibleVersionDiscoveryInput",
    "discover_compatible_versions",
    "discover_compatible_version_candidates",
    "compatible_version_discovery",
]
