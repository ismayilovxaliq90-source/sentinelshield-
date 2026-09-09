from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
import json


@dataclass(frozen=True)
class EcosystemAdvisory:
    advisory_id: str
    ecosystem: str
    package_name: str
    summary: str | None
    details: str | None
    aliases: tuple[str, ...]
    affected_versions: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class EcosystemAdvisoryIngestionResult:
    advisories: tuple[EcosystemAdvisory, ...]
    ingested: bool
    status: str


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    result = []
    for item in value:
        if isinstance(item, str) and item.strip():
            value = item.strip()
            if value not in result:
                result.append(value)
    return tuple(result)


def _parse_item(item: Any):
    if not isinstance(item, Mapping):
        return None, "INVALID_ADVISORY"

    advisory_id = _text(
        item.get("id", item.get("advisory_id"))
    )
    ecosystem = _text(item.get("ecosystem"))
    package_name = _text(
        item.get("package_name", item.get("package"))
    )

    if advisory_id is None:
        return None, "ADVISORY_ID_MISSING"

    if ecosystem is None:
        return None, "ECOSYSTEM_MISSING"

    if package_name is None:
        return None, "PACKAGE_NAME_MISSING"

    affected = item.get(
        "affected_versions",
        item.get("affected", []),
    )
    fixed = item.get(
        "fixed_versions",
        item.get("fixed", []),
    )

    if affected is None:
        affected = []

    if fixed is None:
        fixed = []

    if not isinstance(affected, (list, tuple)):
        return None, "INVALID_AFFECTED_VERSIONS"

    if not isinstance(fixed, (list, tuple)):
        return None, "INVALID_FIXED_VERSIONS"

    return (
        EcosystemAdvisory(
            advisory_id=advisory_id,
            ecosystem=ecosystem.strip().lower(),
            package_name=package_name,
            summary=_text(item.get("summary")),
            details=_text(item.get("details")),
            aliases=_strings(item.get("aliases", [])),
            affected_versions=_strings(affected),
            fixed_versions=_strings(fixed),
            raw=dict(item),
        ),
        "VALID",
    )


def ingest_ecosystem_advisories(
    payload: Any,
) -> EcosystemAdvisoryIngestionResult:

    if payload is None:
        return EcosystemAdvisoryIngestionResult(
            advisories=(),
            ingested=False,
            status="PAYLOAD_IS_NONE",
        )

    if isinstance(payload, (str, bytes, bytearray)):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return EcosystemAdvisoryIngestionResult(
                advisories=(),
                ingested=False,
                status="INVALID_JSON",
            )

    if not isinstance(payload, Mapping):
        return EcosystemAdvisoryIngestionResult(
            advisories=(),
            ingested=False,
            status="INVALID_RESPONSE",
        )

    values = payload.get("advisories")

    if values is None:
        if "id" in payload:
            values = [payload]
        else:
            return EcosystemAdvisoryIngestionResult(
                advisories=(),
                ingested=False,
                status="ADVISORIES_NOT_FOUND",
            )

    if not isinstance(values, (list, tuple)):
        return EcosystemAdvisoryIngestionResult(
            advisories=(),
            ingested=False,
            status="INVALID_ADVISORIES_COLLECTION",
        )

    advisories = []

    for item in values:
        advisory, status = _parse_item(item)

        if advisory is None:
            return EcosystemAdvisoryIngestionResult(
                advisories=(),
                ingested=False,
                status=status,
            )

        advisories.append(advisory)

    advisories.sort(
        key=lambda item: (
            item.ecosystem.casefold(),
            item.package_name.casefold(),
            item.advisory_id.casefold(),
        )
    )

    if not advisories:
        return EcosystemAdvisoryIngestionResult(
            advisories=(),
            ingested=True,
            status="NO_ADVISORIES",
        )

    return EcosystemAdvisoryIngestionResult(
        advisories=tuple(advisories),
        ingested=True,
        status="ADVISORIES_INGESTED",
    )


def ingest_ecosystem_advisory_json(
    payload: str | bytes | bytearray,
) -> EcosystemAdvisoryIngestionResult:
    return ingest_ecosystem_advisories(payload)
