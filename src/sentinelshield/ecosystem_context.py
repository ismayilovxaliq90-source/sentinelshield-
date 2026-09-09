from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


VALID_CONFIDENCE = {"NONE", "LOW", "MEDIUM", "HIGH"}


@dataclass(frozen=True)
class EcosystemRecord:
    name: str
    detected: bool
    confidence: str
    markers: tuple[Path, ...]
    marker_types: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class EcosystemContext:
    root: Path | None
    ecosystems: tuple[EcosystemRecord, ...]
    detected_ecosystems: tuple[str, ...]
    primary_ecosystem: str | None
    ecosystem_count: int
    confidence: str
    reason: str


def _normalize_record(value: Any) -> EcosystemRecord | None:
    if isinstance(value, EcosystemRecord):
        record = value
    else:
        try:
            name = str(value["name"]).strip().lower()
            detected = bool(value["detected"])
            confidence = str(value.get("confidence", "NONE")).upper()
            markers = tuple(
                sorted(
                    (Path(item) for item in value.get("markers", ())),
                    key=lambda p: p.as_posix(),
                )
            )
            marker_types = tuple(
                sorted(
                    {str(item) for item in value.get("marker_types", ())}
                )
            )
            reason = str(value.get("reason", ""))
        except (AttributeError, KeyError, TypeError, ValueError):
            return None

        record = EcosystemRecord(
            name=name,
            detected=detected,
            confidence=confidence,
            markers=markers,
            marker_types=marker_types,
            reason=reason,
        )

    if not record.name:
        return None

    confidence = record.confidence.upper()
    if confidence not in VALID_CONFIDENCE:
        confidence = "NONE"

    markers = tuple(
        sorted(
            {Path(item) for item in record.markers},
            key=lambda p: p.as_posix(),
        )
    )

    marker_types = tuple(sorted(set(record.marker_types)))

    return EcosystemRecord(
        name=record.name.lower(),
        detected=record.detected,
        confidence=confidence,
        markers=markers,
        marker_types=marker_types,
        reason=record.reason,
    )


def _confidence_rank(value: str) -> int:
    return {
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }.get(value, 0)


def generate_ecosystem_context(
    root: Any,
    records: Iterable[Any],
) -> EcosystemContext:
    if root is None:
        return EcosystemContext(
            None, (), (), None, 0, "NONE", "PATH_IS_NONE"
        )

    if not isinstance(root, (str, Path)):
        return EcosystemContext(
            None, (), (), None, 0, "NONE",
            "UNSUPPORTED_PATH_TYPE",
        )

    if isinstance(root, str):
        root = root.strip()
        if not root:
            return EcosystemContext(
                None, (), (), None, 0, "NONE", "PATH_IS_EMPTY"
            )

    raw = str(root)

    if "\x00" in raw:
        return EcosystemContext(
            None, (), (), None, 0, "NONE",
            "NULL_CHARACTER_NOT_ALLOWED",
        )

    try:
        resolved_root = Path(root).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return EcosystemContext(
            None, (), (), None, 0, "NONE",
            f"PATH_RESOLUTION_FAILED:{type(exc).__name__}",
        )

    if not resolved_root.exists():
        return EcosystemContext(
            resolved_root, (), (), None, 0, "NONE",
            "PATH_DOES_NOT_EXIST",
        )

    if not resolved_root.is_dir():
        return EcosystemContext(
            resolved_root, (), (), None, 0, "NONE",
            "PATH_IS_NOT_DIRECTORY",
        )

    normalized: dict[str, EcosystemRecord] = {}

    try:
        source_records = list(records)
    except (TypeError, ValueError):
        source_records = []

    for item in source_records:
        record = _normalize_record(item)

        if record is None:
            continue

        existing = normalized.get(record.name)

        if existing is None:
            normalized[record.name] = record
            continue

        if _confidence_rank(record.confidence) > _confidence_rank(
            existing.confidence
        ):
            normalized[record.name] = record
        elif (
            _confidence_rank(record.confidence)
            == _confidence_rank(existing.confidence)
            and len(record.markers) > len(existing.markers)
        ):
            normalized[record.name] = record

    ecosystems = tuple(
        sorted(
            normalized.values(),
            key=lambda item: item.name,
        )
    )

    detected = tuple(
        record.name
        for record in ecosystems
        if record.detected
    )

    detected_records = [
        record for record in ecosystems if record.detected
    ]

    if not detected_records:
        return EcosystemContext(
            resolved_root,
            ecosystems,
            (),
            None,
            0,
            "NONE",
            "NO_ECOSYSTEM_DETECTED",
        )

    primary = max(
        detected_records,
        key=lambda record: (
            _confidence_rank(record.confidence),
            len(record.markers),
            record.name,
        ),
    )

    overall_confidence = max(
        (record.confidence for record in detected_records),
        key=_confidence_rank,
    )

    if len(detected) > 1:
        reason = "MULTI_ECOSYSTEM_CONTEXT_CREATED"
    else:
        reason = "ECOSYSTEM_CONTEXT_CREATED"

    return EcosystemContext(
        resolved_root,
        ecosystems,
        detected,
        primary.name,
        len(detected),
        overall_confidence,
        reason,
    )
