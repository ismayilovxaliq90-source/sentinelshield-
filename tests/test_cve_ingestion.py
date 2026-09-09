import pytest

from sentinelshield.cve_ingestion import (
    CVEIngestionResult,
    CVERecord,
    ingest_cve_record,
    ingest_cve_records,
)


def test_cve_record_is_ingested():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2025-1234",
            "summary": "Example vulnerability",
            "published": "2025-01-01T00:00:00Z",
            "modified": "2025-01-02T00:00:00Z",
            "references": [
                "https://example.com/advisory",
            ],
        }
    )

    assert result.ingested is True
    assert result.status == "CVE_INGESTED"
    assert result.records == (
        CVERecord(
            cve_id="CVE-2025-1234",
            summary="Example vulnerability",
            published="2025-01-01T00:00:00Z",
            modified="2025-01-02T00:00:00Z",
            references=("https://example.com/advisory",),
        ),
    )


def test_cve_id_alias_is_supported():
    result = ingest_cve_record(
        {
            "id": "CVE-2024-0001",
        }
    )

    assert result.ingested is True
    assert result.records[0].cve_id == "CVE-2024-0001"


def test_cve_id_is_normalized_to_uppercase():
    result = ingest_cve_record(
        {
            "cve_id": "cve-2024-0001",
        }
    )

    assert result.records[0].cve_id == "CVE-2024-0001"


def test_cve_id_whitespace_is_removed():
    result = ingest_cve_record(
        {
            "cve_id": "  CVE-2024-0001  ",
        }
    )

    assert result.records[0].cve_id == "CVE-2024-0001"


def test_summary_is_optional():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2024-0001",
        }
    )

    assert result.records[0].summary is None


def test_published_is_optional():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2024-0001",
        }
    )

    assert result.records[0].published is None


def test_modified_is_optional():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2024-0001",
        }
    )

    assert result.records[0].modified is None


def test_references_are_preserved():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2024-0001",
            "references": [
                "https://b.example",
                "https://a.example",
            ],
        }
    )

    assert result.records[0].references == (
        "https://a.example",
        "https://b.example",
    )


def test_reference_dict_form_is_supported():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2024-0001",
            "references": [
                {"url": "https://example.com/advisory"},
            ],
        }
    )

    assert result.records[0].references == (
        "https://example.com/advisory",
    )


def test_duplicate_references_are_removed():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2024-0001",
            "references": [
                "https://example.com",
                "https://example.com",
            ],
        }
    )

    assert result.records[0].references == (
        "https://example.com",
    )


def test_empty_reference_values_are_removed():
    result = ingest_cve_record(
        {
            "cve_id": "CVE-2024-0001",
            "references": [
                "",
                "  ",
                "https://example.com",
            ],
        }
    )

    assert result.records[0].references == (
        "https://example.com",
    )


def test_empty_inventory_is_valid():
    result = ingest_cve_records(())

    assert result.ingested is True
    assert result.status == "CVE_INGESTED"
    assert result.records == ()


def test_none_inventory_is_rejected():
    result = ingest_cve_records(None)

    assert result.ingested is False
    assert result.status == "RECORDS_IS_NONE"
    assert result.records == ()


def test_string_inventory_is_rejected():
    result = ingest_cve_records("CVE-2024-0001")

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = ingest_cve_records(b"CVE-2024-0001")

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_dict_inventory_is_rejected():
    result = ingest_cve_records(
        {"cve_id": "CVE-2024-0001"}
    )

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = ingest_cve_records(123)

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_invalid_record_type_is_rejected():
    result = ingest_cve_records([123])

    assert result.ingested is False
    assert result.status == "INVALID_CVE_RECORD"


def test_missing_cve_id_is_rejected():
    result = ingest_cve_records(
        [{"summary": "missing identifier"}]
    )

    assert result.ingested is False
    assert result.status == "INVALID_CVE_RECORD"


def test_invalid_cve_id_is_rejected():
    result = ingest_cve_records(
        [{"cve_id": "GHSA-xxxx"}]
    )

    assert result.ingested is False
    assert result.status == "INVALID_CVE_RECORD"


def test_multiple_records_are_sorted():
    result = ingest_cve_records(
        [
            {"cve_id": "CVE-2025-0002"},
            {"cve_id": "CVE-2024-0001"},
            {"cve_id": "CVE-2025-0001"},
        ]
    )

    assert [r.cve_id for r in result.records] == [
        "CVE-2024-0001",
        "CVE-2025-0001",
        "CVE-2025-0002",
    ]


def test_result_is_immutable():
    result = ingest_cve_record(
        {"cve_id": "CVE-2024-0001"}
    )

    with pytest.raises(AttributeError):
        result.ingested = False


def test_cve_record_is_immutable():
    record = CVERecord(
        cve_id="CVE-2024-0001",
        summary=None,
        published=None,
        modified=None,
        references=(),
    )

    with pytest.raises(AttributeError):
        record.cve_id = "changed"


def test_result_type_is_correct():
    result = ingest_cve_record(
        {"cve_id": "CVE-2024-0001"}
    )

    assert isinstance(result, CVEIngestionResult)


def test_record_type_is_correct():
    result = ingest_cve_record(
        {"cve_id": "CVE-2024-0001"}
    )

    assert isinstance(result.records[0], CVERecord)


def test_input_is_not_modified():
    records = [
        {
            "cve_id": "CVE-2024-0002",
            "references": ["https://example.com"],
        },
        {
            "cve_id": "CVE-2024-0001",
        },
    ]

    original = [dict(item) for item in records]

    ingest_cve_records(records)

    assert records == original
