from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class BreakingChangeAssessment:
    package_name: str
    current_version: str
    candidate_version: str
    current_major: int
    candidate_major: int
    major_changed: bool
    minor_changed: bool
    patch_changed: bool
    breaking_change: bool
    change_type: str
    reason: str
    original_index: int


@dataclass(frozen=True)
class BreakingChangeDetectionResult:
    assessments: tuple[BreakingChangeAssessment, ...]
    total: int
    breaking_count: int
    non_breaking_count: int


@dataclass(frozen=True)
class BreakingChangeDetectionInput:
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


def detect_breaking_changes(
    package_name: str,
    current_version: str,
    candidate_versions: Sequence[str],
    vulnerability_id: Optional[str] = None,
) -> BreakingChangeDetectionResult:
    package_name = _validate_package_name(package_name)

    if not isinstance(current_version, str):
        raise TypeError("CURRENT_VERSION_MUST_BE_STRING")

    current_version = current_version.strip()
    current = _parse_version(current_version)

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

    assessments: list[BreakingChangeAssessment] = []
    seen: set[tuple[int, int, int]] = set()

    for index, raw_version in enumerate(candidate_versions):
        if not isinstance(raw_version, str):
            raise TypeError(
                f"CANDIDATE_VERSION_MUST_BE_STRING:{index}"
            )

        candidate_version = raw_version.strip()
        candidate = _parse_version(candidate_version)

        if candidate in seen:
            continue

        seen.add(candidate)

        current_major, current_minor, current_patch = current
        candidate_major, candidate_minor, candidate_patch = candidate

        major_changed = candidate_major != current_major
        minor_changed = candidate_minor != current_minor
        patch_changed = candidate_patch != current_patch

        if major_changed:
            breaking_change = True
            change_type = "MAJOR"
            reason = "MAJOR_VERSION_CHANGE"
        elif minor_changed:
            breaking_change = False
            change_type = "MINOR"
            reason = "MINOR_VERSION_CHANGE"
        elif patch_changed:
            breaking_change = False
            change_type = "PATCH"
            reason = "PATCH_VERSION_CHANGE"
        else:
            breaking_change = False
            change_type = "NONE"
            reason = "NO_VERSION_CHANGE"

        assessments.append(
            BreakingChangeAssessment(
                package_name=package_name,
                current_version=current_version,
                candidate_version=candidate_version,
                current_major=current_major,
                candidate_major=candidate_major,
                major_changed=major_changed,
                minor_changed=minor_changed,
                patch_changed=patch_changed,
                breaking_change=breaking_change,
                change_type=change_type,
                reason=reason,
                original_index=index,
            )
        )

    assessments.sort(
        key=lambda item: (
            item.breaking_change,
            _parse_version(item.candidate_version),
            item.original_index,
        )
    )

    breaking_count = sum(
        item.breaking_change for item in assessments
    )

    return BreakingChangeDetectionResult(
        assessments=tuple(assessments),
        total=len(assessments),
        breaking_count=breaking_count,
        non_breaking_count=len(assessments) - breaking_count,
    )


# Public aliases.
breaking_change_detection = detect_breaking_changes
detect_breaking_change = detect_breaking_changes


__all__ = [
    "BreakingChangeAssessment",
    "BreakingChangeDetectionResult",
    "BreakingChangeDetectionInput",
    "detect_breaking_changes",
    "breaking_change_detection",
    "detect_breaking_change",
]
