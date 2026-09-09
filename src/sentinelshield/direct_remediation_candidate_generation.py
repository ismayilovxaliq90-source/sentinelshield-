from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class DirectRemediationCandidate:
    vulnerability_id: Optional[str]
    package_name: str
    current_version: str
    candidate_version: str
    source: str
    is_direct: bool
    is_upgrade: bool
    original_index: int


@dataclass(frozen=True)
class DirectRemediationCandidateGenerationResult:
    candidates: tuple[DirectRemediationCandidate, ...]
    total: int


@dataclass(frozen=True)
class DirectRemediationCandidateGenerationInput:
    vulnerability_id: Optional[str]
    package_name: str
    current_version: str
    candidate_versions: Sequence[str]
    source: str = "direct"


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


def generate_direct_remediation_candidates(
    vulnerability_id: Optional[str],
    package_name: str,
    current_version: str,
    candidate_versions: Sequence[str],
    source: str = "direct",
) -> DirectRemediationCandidateGenerationResult:
    if vulnerability_id is not None:
        if not isinstance(vulnerability_id, str):
            raise TypeError(
                "VULNERABILITY_ID_MUST_BE_STRING_OR_NONE"
            )
        vulnerability_id = vulnerability_id.strip()

    package_name = _validate_package_name(package_name)

    if not isinstance(current_version, str):
        raise TypeError("CURRENT_VERSION_MUST_BE_STRING")

    current_version = current_version.strip()
    current_key = _parse_version(current_version)

    if isinstance(candidate_versions, (str, bytes, bytearray)):
        raise TypeError("CANDIDATE_VERSIONS_MUST_BE_SEQUENCE")

    if not isinstance(candidate_versions, Sequence):
        raise TypeError("CANDIDATE_VERSIONS_MUST_BE_SEQUENCE")

    if not isinstance(source, str):
        raise TypeError("SOURCE_MUST_BE_STRING")

    source = source.strip()

    if not source:
        raise ValueError("SOURCE_IS_EMPTY")

    seen: set[tuple[int, int, int]] = set()
    candidates: list[DirectRemediationCandidate] = []

    for index, raw_version in enumerate(candidate_versions):
        if not isinstance(raw_version, str):
            raise TypeError(
                f"CANDIDATE_VERSION_MUST_BE_STRING:{index}"
            )

        candidate_version = raw_version.strip()
        candidate_key = _parse_version(candidate_version)

        # Only genuine upgrades are remediation candidates.
        if candidate_key <= current_key:
            continue

        # Remove semantic duplicates such as 1.2.4 and v1.2.4.
        if candidate_key in seen:
            continue

        seen.add(candidate_key)

        candidates.append(
            DirectRemediationCandidate(
                vulnerability_id=vulnerability_id,
                package_name=package_name,
                current_version=current_version,
                candidate_version=candidate_version,
                source=source,
                is_direct=True,
                is_upgrade=True,
                original_index=index,
            )
        )

    def sort_key(
        candidate: DirectRemediationCandidate,
    ) -> tuple[int, int, int, int]:
        major, minor, patch = _parse_version(
            candidate.candidate_version
        )

        current_major, current_minor, current_patch = current_key

        return (
            major - current_major,
            minor - current_minor,
            patch - current_patch,
            candidate.original_index,
        )

    candidates.sort(key=sort_key)

    return DirectRemediationCandidateGenerationResult(
        candidates=tuple(candidates),
        total=len(candidates),
    )


# Public aliases.
direct_remediation_candidate_generation = (
    generate_direct_remediation_candidates
)

generate_direct_candidates = generate_direct_remediation_candidates


__all__ = [
    "DirectRemediationCandidate",
    "DirectRemediationCandidateGenerationResult",
    "DirectRemediationCandidateGenerationInput",
    "generate_direct_remediation_candidates",
    "direct_remediation_candidate_generation",
    "generate_direct_candidates",
]
