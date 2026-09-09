from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class FixedVersionCandidate:
    vulnerability_id: str
    package_name: str
    current_version: str
    fixed_version: str
    source: str
    is_upgrade: bool
    original_index: int


@dataclass(frozen=True)
class FixedVersionCandidateDiscoveryResult:
    candidates: tuple[FixedVersionCandidate, ...]
    total: int
    vulnerabilities_processed: int


@dataclass(frozen=True)
class FixedVersionDiscoveryInput:
    vulnerability_id: str
    package_name: str
    current_version: str
    fixed_versions: tuple[str, ...]
    source: str = "UNKNOWN"


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")

    value = value.strip()

    if not value:
        raise ValueError(f"{field} must not be empty")

    return value


def _version_key(version: str) -> tuple[Any, ...]:
    """
    Deterministic comparison for common dependency versions.

    Numeric components are compared numerically.
    Non-numeric components are compared lexically.
    """
    value = _required_text(version, "version")

    parts = value.split(".")
    result: list[Any] = []

    for part in parts:
        part = part.strip()

        if part.isdigit():
            result.append((0, int(part)))
        else:
            result.append((1, part.lower()))

    return tuple(result)


def _is_fixed_version_newer(
    current_version: str,
    fixed_version: str,
) -> bool:
    try:
        return _version_key(fixed_version) > _version_key(current_version)
    except (TypeError, ValueError):
        return fixed_version != current_version


def _normalize_item(
    value: FixedVersionDiscoveryInput | Mapping[str, Any],
) -> FixedVersionDiscoveryInput:
    if isinstance(value, FixedVersionDiscoveryInput):
        fixed_versions = value.fixed_versions

        if not isinstance(fixed_versions, tuple):
            raise TypeError("fixed_versions must be a tuple")

        normalized_versions = tuple(
            _required_text(version, "fixed_version")
            for version in fixed_versions
        )

        return FixedVersionDiscoveryInput(
            vulnerability_id=_required_text(
                value.vulnerability_id,
                "vulnerability_id",
            ),
            package_name=_required_text(
                value.package_name,
                "package_name",
            ),
            current_version=_required_text(
                value.current_version,
                "current_version",
            ),
            fixed_versions=normalized_versions,
            source=_required_text(
                value.source,
                "source",
            ),
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
                + ", ".join(sorted(str(x) for x in unknown))
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
                + ", ".join(sorted(missing))
            )

        fixed_versions = value["fixed_versions"]

        if isinstance(fixed_versions, (str, bytes, bytearray)):
            raise TypeError(
                "fixed_versions must be a sequence of versions"
            )

        try:
            normalized_versions = tuple(
                _required_text(version, "fixed_version")
                for version in fixed_versions
            )
        except TypeError as exc:
            raise TypeError(
                "fixed_versions must be a sequence of versions"
            ) from exc

        source = value.get("source", "UNKNOWN")

        return FixedVersionDiscoveryInput(
            vulnerability_id=_required_text(
                value["vulnerability_id"],
                "vulnerability_id",
            ),
            package_name=_required_text(
                value["package_name"],
                "package_name",
            ),
            current_version=_required_text(
                value["current_version"],
                "current_version",
            ),
            fixed_versions=normalized_versions,
            source=_required_text(source, "source"),
        )

    raise TypeError(
        "Item must be FixedVersionDiscoveryInput or Mapping"
    )


def discover_fixed_version_candidates(
    values: Sequence[
        FixedVersionDiscoveryInput | Mapping[str, Any]
    ],
) -> FixedVersionCandidateDiscoveryResult:
    if values is None:
        raise TypeError("Input must not be None")

    if isinstance(values, (str, bytes, bytearray)):
        raise TypeError("Input must be a sequence of vulnerability records")

    try:
        source_items = list(values)
    except TypeError as exc:
        raise TypeError(
            "Input must be a sequence of vulnerability records"
        ) from exc

    candidates: list[FixedVersionCandidate] = []

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

            # A fixed version equal to or older than the current
            # version is not an upgrade candidate.
            if not _is_fixed_version_newer(
                item.current_version,
                fixed_version,
            ):
                continue

            candidates.append(
                FixedVersionCandidate(
                    vulnerability_id=item.vulnerability_id,
                    package_name=item.package_name,
                    current_version=item.current_version,
                    fixed_version=fixed_version,
                    source=item.source,
                    is_upgrade=True,
                    original_index=original_index,
                )
            )

    # Deterministic ordering:
    # vulnerability/input order first, then version order.
    candidates.sort(
        key=lambda candidate: (
            candidate.original_index,
            _version_key(candidate.fixed_version),
        )
    )

    return FixedVersionCandidateDiscoveryResult(
        candidates=tuple(candidates),
        total=len(candidates),
        vulnerabilities_processed=len(source_items),
    )


# Public alias.
fixed_version_candidate_discovery = discover_fixed_version_candidates
