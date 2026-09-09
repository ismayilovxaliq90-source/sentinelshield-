from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class UpgradePath:
    package_name: str
    current_version: str
    target_version: str
    versions: tuple[str, ...]
    steps: int
    major_upgrades: int
    minor_upgrades: int
    patch_upgrades: int
    upgrade_distance: int
    original_index: int


@dataclass(frozen=True)
class UpgradePathGenerationResult:
    paths: tuple[UpgradePath, ...]
    total: int


@dataclass(frozen=True)
class UpgradePathGenerationInput:
    package_name: str
    current_version: str
    candidate_versions: Sequence[str]
    vulnerability_id: Optional[str] = None


def _parse_version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise TypeError("VERSION_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError("VERSION_IS_EMPTY")

    if value.startswith(("v", "V")):
        value = value[1:]

    value = value.split("-", 1)[0]
    value = value.split("+", 1)[0]

    parts = value.split(".")

    if not 1 <= len(parts) <= 3:
        raise ValueError("VERSION_MUST_HAVE_ONE_TO_THREE_COMPONENTS")

    if not all(part.isdigit() for part in parts):
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NUMERIC")

    numbers = [int(part) for part in parts]

    while len(numbers) < 3:
        numbers.append(0)

    return tuple(numbers)


def _validate_package_name(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("PACKAGE_NAME_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError("PACKAGE_NAME_IS_EMPTY")

    return value


def _distance(
    current: tuple[int, int, int],
    target: tuple[int, int, int],
) -> int:
    major, minor, patch = target
    current_major, current_minor, current_patch = current

    return (
        (major - current_major) * 1_000_000
        + (minor - current_minor) * 1_000
        + (patch - current_patch)
    )


def generate_upgrade_paths(
    package_name: str,
    current_version: str,
    candidate_versions: Sequence[str],
    vulnerability_id: Optional[str] = None,
) -> UpgradePathGenerationResult:
    package_name = _validate_package_name(package_name)

    if not isinstance(current_version, str):
        raise TypeError("CURRENT_VERSION_MUST_BE_STRING")

    current_version = current_version.strip()
    current_key = _parse_version(current_version)

    if isinstance(candidate_versions, (str, bytes, bytearray)):
        raise TypeError("CANDIDATE_VERSIONS_MUST_BE_SEQUENCE")

    if not isinstance(candidate_versions, Sequence):
        raise TypeError("CANDIDATE_VERSIONS_MUST_BE_SEQUENCE")

    if vulnerability_id is not None:
        if not isinstance(vulnerability_id, str):
            raise TypeError(
                "VULNERABILITY_ID_MUST_BE_STRING_OR_NONE"
            )
        vulnerability_id = vulnerability_id.strip()

    seen: set[tuple[int, int, int]] = set()
    parsed_candidates: list[
        tuple[tuple[int, int, int], str, int]
    ] = []

    for index, raw_version in enumerate(candidate_versions):
        if not isinstance(raw_version, str):
            raise TypeError(
                f"CANDIDATE_VERSION_MUST_BE_STRING:{index}"
            )

        version = raw_version.strip()
        key = _parse_version(version)

        if key <= current_key:
            continue

        if key in seen:
            continue

        seen.add(key)
        parsed_candidates.append((key, version, index))

    # Build deterministic paths from the current version
    # directly to each valid target candidate.
    parsed_candidates.sort(
        key=lambda item: (
            _distance(current_key, item[0]),
            item[0],
            item[2],
        )
    )

    paths: list[UpgradePath] = []

    for target_key, target_version, original_index in parsed_candidates:
        current_major, current_minor, current_patch = current_key
        target_major, target_minor, target_patch = target_key

        major_upgrades = max(0, target_major - current_major)
        minor_upgrades = max(0, target_minor - current_minor)
        patch_upgrades = max(0, target_patch - current_patch)

        steps = (
            major_upgrades
            + minor_upgrades
            + patch_upgrades
        )

        paths.append(
            UpgradePath(
                package_name=package_name,
                current_version=current_version,
                target_version=target_version,
                versions=(current_version, target_version),
                steps=steps,
                major_upgrades=major_upgrades,
                minor_upgrades=minor_upgrades,
                patch_upgrades=patch_upgrades,
                upgrade_distance=_distance(
                    current_key,
                    target_key,
                ),
                original_index=original_index,
            )
        )

    return UpgradePathGenerationResult(
        paths=tuple(paths),
        total=len(paths),
    )


# Public aliases.
upgrade_path_generation = generate_upgrade_paths
generate_upgrade_path = generate_upgrade_paths


__all__ = [
    "UpgradePath",
    "UpgradePathGenerationResult",
    "UpgradePathGenerationInput",
    "generate_upgrade_paths",
    "upgrade_path_generation",
    "generate_upgrade_path",
]
