from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class GHSARecord:
    ghsa_id: str
    summary: str | None
    description: str | None
    published: str | None
    modified: str | None
    references: tuple[str, ...]


@dataclass(frozen=True)
class GHSAIngestionResult:
    records: tuple[GHSARecord, ...]
    ingested: bool
    status: str


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value else None


def _references(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()

    if isinstance(value, str):
        value = (value,)

    try:
        items = tuple(value)
    except TypeError:
        return ()

    references: set[str] = set()

    for item in items:
        if isinstance(item, str):
            value = item.strip()
            if value:
                references.add(value)

        elif isinstance(item, dict):
            url = item.get("url")
            if isinstance(url, str):
                url = url.strip()
                if url:
                    references.add(url)

    return tuple(sorted(references))


def _extract_ghsa(item: Any) -> GHSARecord | None:
    if not isinstance(item, dict):
        return None

    ghsa_id = item.get("ghsa_id")

    if ghsa_id is None:
        ghsa_id = item.get("id")

    if not isinstance(ghsa_id, str):
        return None

    ghsa_id = ghsa_id.strip().upper()

    if not ghsa_id.startswith("GHSA-"):
        return None

    return GHSARecord(
        ghsa_id=ghsa_id,
        summary=_text(item.get("summary")),
        description=_text(item.get("description")),
        published=_text(item.get("published")),
        modified=_text(item.get("modified")),
        references=_references(item.get("references")),
    )


def ingest_ghsa_records(
    records: Iterable[Any] | Any,
) -> GHSAIngestionResult:
    """
    TASK 104 — GHSA Ingestion.

    Converts already available GHSA records into immutable
    normalized GHSARecord objects.

    Read-only operation.

    Does not:
      - query GitHub
      - execute scanners
      - install packages
      - modify files
      - modify manifests or lockfiles
      - execute project code
    """

    if records is None:
        return GHSAIngestionResult(
            records=(),
            ingested=False,
            status="RECORDS_IS_NONE",
        )

    if isinstance(records, (str, bytes, dict)):
        return GHSAIngestionResult(
            records=(),
            ingested=False,
            status="UNSUPPORTED_RECORD_COLLECTION",
        )

    try:
        items = tuple(records)
    except TypeError:
        return GHSAIngestionResult(
            records=(),
            ingested=False,
            status="UNSUPPORTED_RECORD_COLLECTION",
        )

    result: list[GHSARecord] = []

    for item in items:
        record = _extract_ghsa(item)

        if record is None:
            return GHSAIngestionResult(
                records=(),
                ingested=False,
                status="INVALID_GHSA_RECORD",
            )

        result.append(record)

    result.sort(
        key=lambda record: (
            record.ghsa_id,
            record.published or "",
            record.modified or "",
        )
    )

    return GHSAIngestionResult(
        records=tuple(result),
        ingested=True,
        status="GHSA_INGESTED",
    )


def ingest_ghsa_record(
    record: Any,
) -> GHSAIngestionResult:
    return ingest_ghsa_records((record,))
