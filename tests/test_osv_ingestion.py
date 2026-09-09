import json

from sentinelshield.osv_ingestion import (
    OSVAdvisory,
    OSVIngestionResult,
    ingest_osv_json,
    ingest_osv_response,
)


def advisory(
    advisory_id,
    summary="Test advisory",
    aliases=None,
):
    return {
        "id": advisory_id,
        "summary": summary,
        "details": "Test details",
        "aliases": aliases or [],
        "modified": "2026-01-01T00:00:00Z",
        "published": "2025-01-01T00:00:00Z",
    }


def test_single_osv_advisory_is_ingested():
    result = ingest_osv_response(
        {"vulns": [advisory("GHSA-1234")]}
    )

    assert isinstance(result, OSVIngestionResult)
    assert result.ingested is True
    assert result.status == "OSV_INGESTED"
    assert len(result.advisories) == 1

    item = result.advisories[0]

    assert isinstance(item, OSVAdvisory)
    assert item.advisory_id == "GHSA-1234"
    assert item.summary == "Test advisory"


def test_multiple_advisories_are_ingested():
    result = ingest_osv_response(
        {
            "vulns": [
                advisory("OSV-2"),
                advisory("OSV-1"),
            ]
        }
    )

    assert result.ingested is True
    assert len(result.advisories) == 2


def test_advisories_are_sorted_deterministically():
    result = ingest_osv_response(
        {
            "vulns": [
                advisory("OSV-003"),
                advisory("OSV-001"),
                advisory("OSV-002"),
            ]
        }
    )

    assert [
        item.advisory_id
        for item in result.advisories
    ] == [
        "OSV-001",
        "OSV-002",
        "OSV-003",
    ]


def test_aliases_are_preserved():
    result = ingest_osv_response(
        {
            "vulns": [
                advisory(
                    "GHSA-1234",
                    aliases=["CVE-2026-1234", "CVE-2026-1234"],
                )
            ]
        }
    )

    assert result.advisories[0].aliases == (
        "CVE-2026-1234",
    )


def test_missing_aliases_are_allowed():
    result = ingest_osv_response(
        {
            "vulns": [
                {
                    "id": "OSV-1",
                    "summary": "Summary",
                }
            ]
        }
    )

    assert result.ingested is True
    assert result.advisories[0].aliases == ()


def test_missing_optional_fields_are_allowed():
    result = ingest_osv_response(
        {
            "vulns": [
                {
                    "id": "OSV-1",
                }
            ]
        }
    )

    item = result.advisories[0]

    assert item.summary is None
    assert item.details is None
    assert item.modified is None
    assert item.published is None
    assert item.withdrawn is None


def test_single_advisory_payload_is_supported():
    result = ingest_osv_response(
        advisory("OSV-1")
    )

    assert result.ingested is True
    assert result.advisories[0].advisory_id == "OSV-1"


def test_json_string_is_supported():
    payload = json.dumps(
        {"vulns": [advisory("OSV-1")]}
    )

    result = ingest_osv_json(payload)

    assert result.ingested is True
    assert result.advisories[0].advisory_id == "OSV-1"


def test_json_bytes_are_supported():
    payload = json.dumps(
        {"vulns": [advisory("OSV-1")]}
    ).encode()

    result = ingest_osv_json(payload)

    assert result.ingested is True


def test_none_payload_is_rejected():
    result = ingest_osv_response(None)

    assert result.ingested is False
    assert result.status == "PAYLOAD_IS_NONE"
    assert result.advisories == ()


def test_invalid_json_is_rejected():
    result = ingest_osv_json("{invalid")

    assert result.ingested is False
    assert result.status == "INVALID_JSON"


def test_invalid_response_type_is_rejected():
    result = ingest_osv_response(123)

    assert result.ingested is False
    assert result.status == "INVALID_OSV_RESPONSE"


def test_missing_vulnerability_collection_is_rejected():
    result = ingest_osv_response(
        {"query": {}}
    )

    assert result.ingested is False
    assert result.status == "OSV_ADVISORIES_NOT_FOUND"


def test_vulns_none_means_no_advisories():
    result = ingest_osv_response(
        {"vulns": None}
    )

    assert result.ingested is True
    assert result.status == "NO_ADVISORIES"
    assert result.advisories == ()


def test_empty_vulnerability_collection_is_valid():
    result = ingest_osv_response(
        {"vulns": []}
    )

    assert result.ingested is True
    assert result.status == "NO_ADVISORIES"
    assert result.advisories == ()


def test_invalid_vulns_collection_is_rejected():
    result = ingest_osv_response(
        {"vulns": "invalid"}
    )

    assert result.ingested is False
    assert result.status == "INVALID_VULNS_COLLECTION"


def test_invalid_advisory_is_rejected():
    result = ingest_osv_response(
        {"vulns": [123]}
    )

    assert result.ingested is False
    assert result.status == "INVALID_ADVISORY"


def test_missing_advisory_id_is_rejected():
    result = ingest_osv_response(
        {
            "vulns": [
                {
                    "summary": "Missing ID",
                }
            ]
        }
    )

    assert result.ingested is False
    assert result.status == "ADVISORY_ID_MISSING"


def test_raw_advisory_data_is_preserved():
    payload = advisory("OSV-1")
    payload["database_specific"] = {
        "custom": "value"
    }

    result = ingest_osv_response(
        {"vulns": [payload]}
    )

    assert result.advisories[0].raw["database_specific"] == {
        "custom": "value"
    }


def test_withdrawn_value_is_preserved():
    payload = advisory("OSV-1")
    payload["withdrawn"] = "2026-02-01T00:00:00Z"

    result = ingest_osv_response(
        {"vulns": [payload]}
    )

    assert (
        result.advisories[0].withdrawn
        == "2026-02-01T00:00:00Z"
    )


def test_result_is_immutable():
    result = ingest_osv_response(
        {"vulns": [advisory("OSV-1")]}
    )

    try:
        result.ingested = False
        assert False
    except AttributeError:
        pass


def test_advisory_is_immutable():
    result = ingest_osv_response(
        {"vulns": [advisory("OSV-1")]}
    )

    try:
        result.advisories[0].advisory_id = "changed"
        assert False
    except AttributeError:
        pass


def test_input_payload_is_not_modified():
    payload = {
        "vulns": [
            advisory("OSV-2"),
            advisory("OSV-1"),
        ]
    }

    original = json.loads(json.dumps(payload))

    ingest_osv_response(payload)

    assert payload == original
