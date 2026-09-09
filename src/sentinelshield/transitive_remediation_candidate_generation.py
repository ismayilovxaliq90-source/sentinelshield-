from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence


@dataclass(frozen=True)
class TransitiveRemediationCandidate:
    vulnerability_id: Optional[str]
    package_name: str
    current_version: str
    candidate_version: str
    source: str
    is_transitive: bool
    is_upgrade: bool
    original_index: int


@dataclass(frozen=True)
class TransitiveRemediationCandidateGenerationResult:
    candidates: tuple[TransitiveRemediationCandidate, ...]
    total: int


@dataclass(frozen=True)
class TransitiveRemediationCandidateGenerationInput:
    vulnerability_id: Optional[str]
    package_name: str
    current_version: str
    candidate_versions: Sequence[str]
    source: str = "transitive"


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


def _validate_name(value: object, error_code: str) -> str:
    if not isinstance(value, str):
        raise TypeError(error_code)

    value = value.strip()

    if not value:
        raise ValueError(f"{error_code.removesuffix('_MUST_BE_STRING')}_IS_EMPTY")

    return value


def generate_transitive_remediation_candidates(
    vulnerability_id: Optional[str],
    package_name: str,
    current_version: str,
    candidate_versions: Sequence[str],
    source: str = "transitive",
) -> TransitiveRemediationCandidateGenerationResult:
    if vulnerability_id is not None:
        if not isinstance(vulnerability_id, str):
            raise TypeError("VULNERABILITY_ID_MUST_BE_STRING_OR_NONE")
        vulnerability_id = vulnerability_id.strip()

    package_name = _validate_name(
        package_name,
        "PACKAGE_NAME_MUST_BE_STRING",
    )

    if not isinstance(current_version, str):
        raise TypeError("CURRENT_VERSION_MUST_BE_STRING")

    current_version = current_version.strip()
    current_key = _parse_version(current_version)

    if not isinstance(candidate_versions, Sequence):
        raise TypeError("CANDIDATE_VERSIONS_MUST_BE_SEQUENCE")

    if isinstance(candidate_versions, (str, bytes, bytearray)):
        raise TypeError("CANDIDATE_VERSIONS_MUST_BE_SEQUENCE")

    if not isinstance(source, str):
        raise TypeError("SOURCE_MUST_BE_STRING")

    source = source.strip()

    if not source:
        raise ValueError("SOURCE_IS_EMPTY")

    seen: set[tuple[int, int, int]] = set()
    candidates: list[TransitiveRemediationCandidate] = []

    for index, raw_version in enumerate(candidate_versions):
        if not isinstance(raw_version, str):
            raise TypeError(
                f"CANDIDATE_VERSION_MUST_BE_STRING:{index}"
            )

        normalized_version = raw_version.strip()
        candidate_key = _parse_version(normalized_version)

        # Remediation candidates must represent actual upgrades.
        if candidate_key <= current_key:
            continue

        # Duplicate semantic versions are removed.
        if candidate_key in seen:
            continue

        seen.add(candidate_key)

        candidates.append(
            TransitiveRemediationCandidate(
                vulnerability_id=vulnerability_id,
                package_name=package_name,
                current_version=current_version,
                candidate_version=normalized_version,
                source=source,
                is_transitive=True,
                is_upgrade=True,
                original_index=index,
            )
        )

    # Deterministic ordering:
    # 1. closest upgrade first
    # 2. semantic version
    # 3. original input position
    candidates.sort(
        key=lambda item: (
            _parse_version(item.candidate_version)[0]
            - current_key[0],
            _parse_version(item.candidate_version)[1]
            - current_key[1],
            _parse_version(item.candidate_version)[2]
            - current_key[2],
            item.original_index,
        )
    )

    return TransitiveRemediationCandidateGenerationResult(
        candidates=tuple(candidates),
        total=len(candidates),
    )


# Public aliases.
transitive_remediation_candidate_generation = (
    generate_transitive_remediation_candidates
)

generate_transitive_candidates = generate_transitive_remediation_candidates


__all__ = [
    "TransitiveRemediationCandidate",
    "TransitiveRemediationCandidateGenerationResult",
    "TransitiveRemediationCandidateGenerationInput",
    "generate_transitive_remediation_candidates",
    "transitive_remediation_candidate_generation",
    "generate_transitive_candidates",
]
