from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class CVERecord:
    cve_id: str
    summary: str | None
    published: str | None
    modified: str | None
    references: tuple[str, ...]


@dataclass(frozen=True)
class CVEIngestionResult:
    records: tuple[CVERecord, ...]
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

    result: list[str] = []

    for item in items:
        if isinstance(item, str):
            item = item.strip()
            if item:
                result.append(item)
            continue

        if isinstance(item, dict):
            url = item.get("url")
            if isinstance(url, str) and url.strip():
                result.append(url.strip())

    return tuple(sorted(set(result)))


def _extract_cve(item: Any) -> CVERecord | None:
    if not isinstance(item, dict):
        return None

    cve_id = item.get("cve_id")

    if cve_id is None:
        cve_id = item.get("id")

    if not isinstance(cve_id, str):
        return None

    cve_id = cve_id.strip().upper()

    if not cve_id.startswith("CVE-"):
        return None

    summary = _text(item.get("summary"))
    published = _text(item.get("published"))
    modified = _text(item.get("modified"))

    return CVERecord(
        cve_id=cve_id,
        summary=summary,
        published=published,
        modified=modified,
        references=_references(item.get("references")),
    )


def ingest_cve_records(
    records: Iterable[Any] | Any,
) -> CVEIngestionResult:
    """
    TASK 103 — CVE Ingestion.

    Converts already available CVE data into immutable normalized
    CVERecord objects.

    Read-only operation.

    Does not:
      - query external services
      - execute scanners
      - install packages
      - modify project files
      - modify manifests or lockfiles
      - execute project code
    """

    if records is None:
        return CVEIngestionResult(
            records=(),
            ingested=False,
            status="RECORDS_IS_NONE",
        )

    if isinstance(records, (str, bytes, dict)):
        return CVEIngestionResult(
            records=(),
            ingested=False,
            status="UNSUPPORTED_RECORD_COLLECTION",
        )

    try:
        items = tuple(records)
    except TypeError:
        return CVEIngestionResult(
            records=(),
            ingested=False,
            status="UNSUPPORTED_RECORD_COLLECTION",
        )

    result: list[CVERecord] = []

    for item in items:
        record = _extract_cve(item)

        if record is None:
            return CVEIngestionResult(
                records=(),
                ingested=False,
                status="INVALID_CVE_RECORD",
            )

        result.append(record)

    result.sort(
        key=lambda record: (
            record.cve_id,
            record.published or "",
            record.modified or "",
        )
    )

    return CVEIngestionResult(
        records=tuple(result),
        ingested=True,
        status="CVE_INGESTED",
    )


def ingest_cve_record(
    record: Any,
) -> CVEIngestionResult:
    return ingest_cve_records((record,))
