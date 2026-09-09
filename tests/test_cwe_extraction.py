from dataclasses import FrozenInstanceError

from sentinelshield.cwe_extraction import (
    CWE,
    CWEExtractionResult,
    extract_cwe,
    extract_cwes,
)


def test_basic_cwe():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    assert result.extracted is True
    assert result.status == "CWE_EXTRACTED"
    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
    )


def test_lowercase_cwe_is_normalized():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "cwe-79",
        }
    )

    assert result.cwes[0].cwe == "CWE-79"


def test_numeric_string_cwe():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "79",
        }
    )

    assert result.cwes[0].cwe == "CWE-79"


def test_integer_cwe():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": 79,
        }
    )

    assert result.cwes[0].cwe == "CWE-79"


def test_cwe_id_alias():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe_id": "CWE-89",
        }
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-89"),
    )


def test_cwe_ids_list():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe_ids": ["CWE-79", "CWE-89"],
        }
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
        CWE("CVE-2026-0001", "CWE-89"),
    )


def test_multiple_cwes_are_sorted():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": ["CWE-89", "CWE-79", "CWE-22"],
        }
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-22"),
        CWE("CVE-2026-0001", "CWE-79"),
        CWE("CVE-2026-0001", "CWE-89"),
    )


def test_duplicate_cwes_are_removed():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": ["CWE-79", "CWE-79", "cwe-79"],
        }
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
    )


def test_weakness_alias():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "weakness": "CWE-79",
        }
    )

    assert result.cwes[0].cwe == "CWE-79"


def test_weaknesses_alias():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "weaknesses": ["CWE-79", "CWE-89"],
        }
    )

    assert len(result.cwes) == 2


def test_nested_weakness_object():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "weaknesses": [
                {"id": "CWE-79"},
                {"id": "CWE-89"},
            ],
        }
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
        CWE("CVE-2026-0001", "CWE-89"),
    )


def test_nested_cwe_id_object():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "weaknesses": [
                {"cwe_id": "CWE-79"},
            ],
        }
    )

    assert result.cwes[0].cwe == "CWE-79"


def test_none_collection():
    result = extract_cwes(None)

    assert result.extracted is False
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.cwes == ()


def test_empty_collection():
    result = extract_cwes([])

    assert result.extracted is False
    assert result.status == "NO_VULNERABILITIES"


def test_string_collection_unsupported():
    result = extract_cwes("CVE-2026-0001")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_bytes_collection_unsupported():
    result = extract_cwes(b"CVE-2026-0001")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_integer_collection_unsupported():
    result = extract_cwes(123)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_missing_cwe():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
        }
    )

    assert result.extracted is False
    assert result.status == "NO_CWE"


def test_none_cwe():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": None,
        }
    )

    assert result.extracted is False
    assert result.status == "NO_CWE"


def test_empty_cwe():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CWE"


def test_invalid_cwe():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "CVE-79",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CWE"


def test_zero_cwe_is_invalid():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": 0,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CWE"


def test_negative_cwe_is_invalid():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": -79,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CWE"


def test_boolean_cwe_is_invalid():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": True,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CWE"


def test_missing_identifier():
    result = extract_cwe(
        {
            "cwe": "CWE-79",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_empty_identifier():
    result = extract_cwe(
        {
            "id": " ",
            "cwe": "CWE-79",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_bytes_identifier_invalid():
    result = extract_cwe(
        {
            "id": b"CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_identifier_normalization():
    result = extract_cwe(
        {
            "id": " cve-2026-0001 ",
            "cwe": "cwe-79",
        }
    )

    assert result.cwes[0].identifier == "CVE-2026-0001"


def test_vulnerability_id_alias():
    result = extract_cwe(
        {
            "vulnerability_id": "CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    assert result.cwes[0].identifier == "CVE-2026-0001"


def test_vuln_id_alias():
    result = extract_cwe(
        {
            "vuln_id": "CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    assert result.cwes[0].identifier == "CVE-2026-0001"


def test_cve_alias():
    result = extract_cwe(
        {
            "cve": "CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    assert result.cwes[0].identifier == "CVE-2026-0001"


def test_ghsa_alias():
    result = extract_cwe(
        {
            "ghsa": "GHSA-AAAA-BBBB-CCCC",
            "cwe": "CWE-79",
        }
    )

    assert result.cwes[0].identifier == "GHSA-AAAA-BBBB-CCCC"


def test_multiple_vulnerabilities():
    result = extract_cwes(
        [
            {
                "id": "CVE-2026-0002",
                "cwe": "CWE-89",
            },
            {
                "id": "CVE-2026-0001",
                "cwe": "CWE-79",
            },
        ]
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
        CWE("CVE-2026-0002", "CWE-89"),
    )


def test_duplicate_vulnerabilities_are_deduplicated():
    result = extract_cwes(
        [
            {
                "id": "CVE-2026-0001",
                "cwe": "CWE-79",
            },
            {
                "id": "CVE-2026-0001",
                "cwe": "CWE-79",
            },
        ]
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
    )


def test_nested_lists():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": [
                ["CWE-79"],
                ["CWE-89"],
            ],
        }
    )

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
        CWE("CVE-2026-0001", "CWE-89"),
    )


def test_object_input():
    class Vulnerability:
        identifier = "CVE-2026-0001"
        cwe = "CWE-79"

    result = extract_cwe(Vulnerability())

    assert result.cwes == (
        CWE("CVE-2026-0001", "CWE-79"),
    )


def test_result_is_frozen():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    try:
        result.extracted = False
        assert False
    except FrozenInstanceError:
        pass


def test_cwe_is_frozen():
    value = CWE(
        "CVE-2026-0001",
        "CWE-79",
    )

    try:
        value.cwe = "CWE-89"
        assert False
    except FrozenInstanceError:
        pass


def test_result_type():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    assert isinstance(result, CWEExtractionResult)


def test_cwe_type():
    result = extract_cwe(
        {
            "id": "CVE-2026-0001",
            "cwe": "CWE-79",
        }
    )

    assert isinstance(result.cwes[0], CWE)


def test_deterministic_result():
    vulnerabilities = [
        {
            "id": "CVE-2026-0002",
            "cwe": "CWE-89",
        },
        {
            "id": "CVE-2026-0001",
            "cwe": "CWE-79",
        },
    ]

    first = extract_cwes(vulnerabilities)
    second = extract_cwes(vulnerabilities)

    assert first == second
