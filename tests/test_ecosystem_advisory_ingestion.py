import json

from sentinelshield.ecosystem_advisory_ingestion import (
    EcosystemAdvisory,
    EcosystemAdvisoryIngestionResult,
    ingest_ecosystem_advisories,
    ingest_ecosystem_advisory_json,
)


def item(
    advisory_id="ADV-1",
    ecosystem="python",
    package_name="requests",
):
    return {
        "id": advisory_id,
        "ecosystem": ecosystem,
        "package_name": package_name,
        "summary": "Security advisory",
        "details": "Security details",
        "aliases": ["CVE-2026-0001"],
        "affected_versions": ["<2.32.0"],
        "fixed_versions": ["2.32.0"],
    }


def test_single_advisory():
    result = ingest_ecosystem_advisories(
        {"advisories": [item()]}
    )

    assert isinstance(result, EcosystemAdvisoryIngestionResult)
    assert result.ingested is True
    assert result.status == "ADVISORIES_INGESTED"
    assert len(result.advisories) == 1
    assert isinstance(result.advisories[0], EcosystemAdvisory)


def test_fields_are_preserved():
    result = ingest_ecosystem_advisories(
        {"advisories": [item()]}
    )

    advisory = result.advisories[0]

    assert advisory.advisory_id == "ADV-1"
    assert advisory.ecosystem == "python"
    assert advisory.package_name == "requests"
    assert advisory.summary == "Security advisory"
    assert advisory.details == "Security details"
    assert advisory.aliases == ("CVE-2026-0001",)
    assert advisory.affected_versions == ("<2.32.0",)
    assert advisory.fixed_versions == ("2.32.0",)


def test_multiple_advisories():
    result = ingest_ecosystem_advisories(
        {
            "advisories": [
                item("ADV-1"),
                item("ADV-2"),
            ]
        }
    )

    assert len(result.advisories) == 2


def test_deterministic_sorting():
    result = ingest_ecosystem_advisories(
        {
            "advisories": [
                item("Z", "python", "zlib"),
                item("A", "node", "axios"),
                item("B", "python", "requests"),
            ]
        }
    )

    assert [
        (x.ecosystem, x.package_name, x.advisory_id)
        for x in result.advisories
    ] == [
        ("node", "axios", "A"),
        ("python", "requests", "B"),
        ("python", "zlib", "Z"),
    ]


def test_empty_collection():
    result = ingest_ecosystem_advisories(
        {"advisories": []}
    )

    assert result.ingested is True
    assert result.status == "NO_ADVISORIES"
    assert result.advisories == ()


def test_none_payload():
    result = ingest_ecosystem_advisories(None)

    assert result.ingested is False
    assert result.status == "PAYLOAD_IS_NONE"


def test_invalid_json():
    result = ingest_ecosystem_advisory_json(
        "{invalid"
    )

    assert result.ingested is False
    assert result.status == "INVALID_JSON"


def test_invalid_response():
    result = ingest_ecosystem_advisories(123)

    assert result.ingested is False
    assert result.status == "INVALID_RESPONSE"


def test_missing_advisories():
    result = ingest_ecosystem_advisories(
        {"status": "ok"}
    )

    assert result.ingested is False
    assert result.status == "ADVISORIES_NOT_FOUND"


def test_invalid_collection():
    result = ingest_ecosystem_advisories(
        {"advisories": "invalid"}
    )

    assert result.ingested is False
    assert result.status == "INVALID_ADVISORIES_COLLECTION"


def test_invalid_advisory():
    result = ingest_ecosystem_advisories(
        {"advisories": [123]}
    )

    assert result.ingested is False
    assert result.status == "INVALID_ADVISORY"


def test_missing_id():
    value = item()
    del value["id"]

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.status == "ADVISORY_ID_MISSING"


def test_missing_ecosystem():
    value = item()
    del value["ecosystem"]

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.status == "ECOSYSTEM_MISSING"


def test_missing_package():
    value = item()
    del value["package_name"]

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.status == "PACKAGE_NAME_MISSING"


def test_invalid_affected_versions():
    value = item()
    value["affected_versions"] = "invalid"

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.status == "INVALID_AFFECTED_VERSIONS"


def test_invalid_fixed_versions():
    value = item()
    value["fixed_versions"] = "invalid"

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.status == "INVALID_FIXED_VERSIONS"


def test_optional_fields_can_be_missing():
    result = ingest_ecosystem_advisories(
        {
            "advisories": [
                {
                    "id": "ADV-1",
                    "ecosystem": "python",
                    "package_name": "requests",
                }
            ]
        }
    )

    advisory = result.advisories[0]

    assert advisory.summary is None
    assert advisory.details is None
    assert advisory.aliases == ()
    assert advisory.affected_versions == ()
    assert advisory.fixed_versions == ()


def test_json_string():
    payload = json.dumps(
        {"advisories": [item()]}
    )

    result = ingest_ecosystem_advisory_json(payload)

    assert result.ingested is True
    assert result.advisories[0].advisory_id == "ADV-1"


def test_single_advisory_payload():
    result = ingest_ecosystem_advisories(
        item()
    )

    assert result.ingested is True
    assert result.advisories[0].advisory_id == "ADV-1"


def test_aliases_are_deduplicated():
    value = item()
    value["aliases"] = [
        "CVE-1",
        "CVE-1",
        "GHSA-1",
    ]

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.advisories[0].aliases == (
        "CVE-1",
        "GHSA-1",
    )


def test_ecosystem_is_normalized():
    value = item()
    value["ecosystem"] = "  PYTHON  "

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.advisories[0].ecosystem == "python"


def test_raw_data_is_preserved():
    value = item()
    value["database_specific"] = {"score": 9.8}

    result = ingest_ecosystem_advisories(
        {"advisories": [value]}
    )

    assert result.advisories[0].raw["database_specific"] == {
        "score": 9.8
    }


def test_input_is_not_modified():
    payload = {
        "advisories": [
            item("B"),
            item("A"),
        ]
    }

    original = json.loads(json.dumps(payload))

    ingest_ecosystem_advisories(payload)

    assert payload == original


def test_result_is_immutable():
    result = ingest_ecosystem_advisories(
        {"advisories": [item()]}
    )

    try:
        result.ingested = False
        assert False
    except AttributeError:
        pass


def test_advisory_is_immutable():
    result = ingest_ecosystem_advisories(
        {"advisories": [item()]}
    )

    try:
        result.advisories[0].advisory_id = "changed"
        assert False
    except AttributeError:
        pass
