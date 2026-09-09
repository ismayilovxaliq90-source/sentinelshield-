import pytest

from sentinelshield.ghsa_ingestion import (
    GHSAIngestionResult,
    GHSARecord,
    ingest_ghsa_record,
    ingest_ghsa_records,
)


def test_ghsa_record_is_ingested():
    result = ingest_ghsa_record(
        {
            "ghsa_id": "GHSA-ABCD-1234-EFGH",
            "summary": "Example vulnerability",
            "description": "Example description",
            "published": "2025-01-01T00:00:00Z",
            "modified": "2025-01-02T00:00:00Z",
            "references": [
                "https://github.com/advisories/GHSA-ABCD-1234-EFGH",
            ],
        }
    )

    assert result.ingested is True
    assert result.status == "GHSA_INGESTED"
    assert result.records == (
        GHSARecord(
            ghsa_id="GHSA-ABCD-1234-EFGH",
            summary="Example vulnerability",
            description="Example description",
            published="2025-01-01T00:00:00Z",
            modified="2025-01-02T00:00:00Z",
            references=(
                "https://github.com/advisories/GHSA-ABCD-1234-EFGH",
            ),
        ),
    )


def test_id_alias_is_supported():
    result = ingest_ghsa_record(
        {"id": "GHSA-abcd-1234-efgh"}
    )

    assert result.ingested is True
    assert result.records[0].ghsa_id == "GHSA-ABCD-1234-EFGH"


def test_ghsa_id_is_normalized():
    result = ingest_ghsa_record(
        {"ghsa_id": "  ghsa-abcd-1234-efgh  "}
    )

    assert result.records[0].ghsa_id == "GHSA-ABCD-1234-EFGH"


def test_summary_is_optional():
    result = ingest_ghsa_record(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    assert result.records[0].summary is None


def test_description_is_optional():
    result = ingest_ghsa_record(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    assert result.records[0].description is None


def test_published_is_optional():
    result = ingest_ghsa_record(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    assert result.records[0].published is None


def test_modified_is_optional():
    result = ingest_ghsa_record(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    assert result.records[0].modified is None


def test_references_are_sorted():
    result = ingest_ghsa_record(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "references": [
                "https://z.example",
                "https://a.example",
            ],
        }
    )

    assert result.records[0].references == (
        "https://a.example",
        "https://z.example",
    )


def test_reference_dict_form_is_supported():
    result = ingest_ghsa_record(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "references": [
                {"url": "https://example.com/advisory"},
            ],
        }
    )

    assert result.records[0].references == (
        "https://example.com/advisory",
    )


def test_duplicate_references_are_removed():
    result = ingest_ghsa_record(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
            "references": [
                "https://example.com",
                "https://example.com",
            ],
        }
    )

    assert result.records[0].references == (
        "https://example.com",
    )


def test_empty_references_are_ignored():
    result = ingest_ghsa_record(
        {
            "ghsa_id": "GHSA-abcd-1234-efgh",
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
    result = ingest_ghsa_records(())

    assert result.ingested is True
    assert result.status == "GHSA_INGESTED"
    assert result.records == ()


def test_none_inventory_is_rejected():
    result = ingest_ghsa_records(None)

    assert result.ingested is False
    assert result.status == "RECORDS_IS_NONE"
    assert result.records == ()


def test_string_inventory_is_rejected():
    result = ingest_ghsa_records("GHSA-abcd-1234-efgh")

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = ingest_ghsa_records(b"GHSA-abcd-1234-efgh")

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_dict_inventory_is_rejected():
    result = ingest_ghsa_records(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = ingest_ghsa_records(123)

    assert result.ingested is False
    assert result.status == "UNSUPPORTED_RECORD_COLLECTION"


def test_invalid_record_type_is_rejected():
    result = ingest_ghsa_records([123])

    assert result.ingested is False
    assert result.status == "INVALID_GHSA_RECORD"


def test_missing_id_is_rejected():
    result = ingest_ghsa_records(
        [{"summary": "missing identifier"}]
    )

    assert result.ingested is False
    assert result.status == "INVALID_GHSA_RECORD"


def test_non_ghsa_identifier_is_rejected():
    result = ingest_ghsa_records(
        [{"ghsa_id": "CVE-2025-1234"}]
    )

    assert result.ingested is False
    assert result.status == "INVALID_GHSA_RECORD"


def test_multiple_records_are_sorted():
    result = ingest_ghsa_records(
        [
            {"ghsa_id": "GHSA-zzzz-0000-yyyy"},
            {"ghsa_id": "GHSA-abcd-0000-efgh"},
            {"ghsa_id": "GHSA-mnop-0000-qrst"},
        ]
    )

    assert [r.ghsa_id for r in result.records] == [
        "GHSA-ABCD-0000-EFGH",
        "GHSA-MNOP-0000-QRST",
        "GHSA-ZZZZ-0000-YYYY",
    ]


def test_result_is_immutable():
    result = ingest_ghsa_record(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    with pytest.raises(AttributeError):
        result.ingested = False


def test_record_is_immutable():
    record = GHSARecord(
        ghsa_id="GHSA-ABCD-1234-EFGH",
        summary=None,
        description=None,
        published=None,
        modified=None,
        references=(),
    )

    with pytest.raises(AttributeError):
        record.ghsa_id = "changed"


def test_result_type_is_correct():
    result = ingest_ghsa_record(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    assert isinstance(result, GHSAIngestionResult)


def test_record_type_is_correct():
    result = ingest_ghsa_record(
        {"ghsa_id": "GHSA-abcd-1234-efgh"}
    )

    assert isinstance(result.records[0], GHSARecord)


def test_input_is_not_modified():
    records = [
        {
            "ghsa_id": "GHSA-abcd-0000-efgh",
            "references": ["https://example.com"],
        },
        {
            "ghsa_id": "GHSA-bbbb-0000-cccc",
        },
    ]

    original = [dict(item) for item in records]

    ingest_ghsa_records(records)

    assert records == original
