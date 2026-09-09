from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class PatchVersionCandidate:
    vulnerability_id: str
    package_name: str
    current_version: str
    fixed_version: str
    source: str
    patch_distance: int
    original_index: int


@dataclass(frozen=True)
class PatchVersionCandidateDetectionResult:
    candidates: tuple[PatchVersionCandidate, ...]
    total: int
    vulnerabilities_processed: int


@dataclass(frozen=True)
class PatchVersionDetectionInput:
    vulnerability_id: str
    package_name: str
    current_version: str
    fixed_versions: tuple[str, ...]
    source: str = "UNKNOWN"


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")

    value = value.strip()

    if not value:
        raise ValueError(f"{field} must not be empty")

    return value


def _parse_version(version: str) -> tuple[int, int, int]:
    """
    Parse the numeric core of a semantic-style version.

    Accepted examples:
        1.2.3
        v1.2.3
        1.2.3-alpha
        1.2.3+build

    The patch-candidate decision is based on the
    major/minor/patch numeric components.
    """
    value = _text(version, "version")

    if value.startswith(("v", "V")):
        value = value[1:]

    numeric_part = value.split("-", 1)[0].split("+", 1)[0]
    parts = numeric_part.split(".")

    if len(parts) != 3:
        raise ValueError(
            f"Unsupported version format: {version}"
        )

    if not all(part.isdigit() for part in parts):
        raise ValueError(
            f"Unsupported version format: {version}"
        )

    major, minor, patch = (int(part) for part in parts)

    if major < 0 or minor < 0 or patch < 0:
        raise ValueError(
            f"Invalid version: {version}"
        )

    return major, minor, patch


def _normalize_item(
    value: PatchVersionDetectionInput | Mapping[str, Any],
) -> PatchVersionDetectionInput:
    if isinstance(value, PatchVersionDetectionInput):
        if not isinstance(value.fixed_versions, tuple):
            raise TypeError("fixed_versions must be a tuple")

        versions = tuple(
            _text(version, "fixed_version")
            for version in value.fixed_versions
        )

        return PatchVersionDetectionInput(
            vulnerability_id=_text(
                value.vulnerability_id,
                "vulnerability_id",
            ),
            package_name=_text(
                value.package_name,
                "package_name",
            ),
            current_version=_text(
                value.current_version,
                "current_version",
            ),
            fixed_versions=versions,
            source=_text(value.source, "source"),
        )

    if isinstance(value, Mapping):
        allowed = {
            "vulnerability_id",
            "package_name",
            "current_version",
            "fixed_versions",
            "source",
        }

        unknown = set(value) - allowed

        if unknown:
            raise TypeError(
                "Unsupported fields: "
                + ", ".join(
                    sorted(str(x) for x in unknown)
                )
            )

        required = {
            "vulnerability_id",
            "package_name",
            "current_version",
            "fixed_versions",
        }

        missing = required - set(value)

        if missing:
            raise ValueError(
                "Missing fields: "
                + ", ".join(
                    sorted(str(x) for x in missing)
                )
            )

        fixed_versions = value["fixed_versions"]

        if isinstance(
            fixed_versions,
            (str, bytes, bytearray),
        ):
            raise TypeError(
                "fixed_versions must be a sequence"
            )

        try:
            versions = tuple(
                _text(version, "fixed_version")
                for version in fixed_versions
            )
        except TypeError as exc:
            raise TypeError(
                "fixed_versions must be a sequence"
            ) from exc

        return PatchVersionDetectionInput(
            vulnerability_id=_text(
                value["vulnerability_id"],
                "vulnerability_id",
            ),
            package_name=_text(
                value["package_name"],
                "package_name",
            ),
            current_version=_text(
                value["current_version"],
                "current_version",
            ),
            fixed_versions=versions,
            source=_text(
                value.get("source", "UNKNOWN"),
                "source",
            ),
        )

    raise TypeError(
        "Item must be PatchVersionDetectionInput or Mapping"
    )


def _patch_candidate(
    current_version: str,
    fixed_version: str,
) -> tuple[bool, int]:
    current = _parse_version(current_version)
    fixed = _parse_version(fixed_version)

    current_major, current_minor, current_patch = current
    fixed_major, fixed_minor, fixed_patch = fixed

    # Fixed version must be newer.
    if fixed <= current:
        return False, 0

    # Patch candidate means major and minor stay unchanged.
    if fixed_major != current_major:
        return False, 0

    if fixed_minor != current_minor:
        return False, 0

    distance = fixed_patch - current_patch

    if distance <= 0:
        return False, 0

    return True, distance


def detect_patch_version_candidates(
    values: Sequence[
        PatchVersionDetectionInput | Mapping[str, Any]
    ],
) -> PatchVersionCandidateDetectionResult:
    if values is None:
        raise TypeError("Input must not be None")

    if isinstance(
        values,
        (str, bytes, bytearray),
    ):
        raise TypeError(
            "Input must be a sequence of vulnerability records"
        )

    try:
        source_items = list(values)
    except TypeError as exc:
        raise TypeError(
            "Input must be a sequence of vulnerability records"
        ) from exc

    candidates: list[PatchVersionCandidate] = []

    for original_index, raw_item in enumerate(source_items):
        if raw_item is None:
            raise ValueError(
                f"Vulnerability item is None at index {original_index}"
            )

        item = _normalize_item(raw_item)

        seen: set[str] = set()

        for fixed_version in item.fixed_versions:
            if fixed_version in seen:
                continue

            seen.add(fixed_version)

            is_patch, distance = _patch_candidate(
                item.current_version,
                fixed_version,
            )

            if not is_patch:
                continue

            candidates.append(
                PatchVersionCandidate(
                    vulnerability_id=item.vulnerability_id,
                    package_name=item.package_name,
                    current_version=item.current_version,
                    fixed_version=fixed_version,
                    source=item.source,
                    patch_distance=distance,
                    original_index=original_index,
                )
            )

    # Deterministic ordering:
    # original vulnerability order,
    # then smallest patch distance,
    # then numeric version.
    candidates.sort(
        key=lambda candidate: (
            candidate.original_index,
            candidate.patch_distance,
            _parse_version(candidate.fixed_version),
        )
    )

    return PatchVersionCandidateDetectionResult(
        candidates=tuple(candidates),
        total=len(candidates),
        vulnerabilities_processed=len(source_items),
    )


# Public alias.
patch_version_candidate_detection = detect_patch_version_candidates
