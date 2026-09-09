from dataclasses import FrozenInstanceError

from sentinelshield.cvss_extraction import (
    CVSS,
    CVSSExtractionResult,
    extract_cvss,
    extract_single_cvss,
)


def test_extract_float_score():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert result.extracted is True
    assert result.status == "CVSS_EXTRACTED"
    assert result.cvss == (
        CVSS("CVE-2026-0001", 9.8),
    )


def test_extract_integer_score():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 7,
        }
    )

    assert result.cvss == (
        CVSS("CVE-2026-0001", 7.0),
    )


def test_extract_string_score():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": "8.7",
        }
    )

    assert result.cvss[0].score == 8.7


def test_whitespace_string_score():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": " 9.1 ",
        }
    )

    assert result.cvss[0].score == 9.1


def test_zero_score():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 0,
        }
    )

    assert result.cvss[0].score == 0.0


def test_ten_score():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 10,
        }
    )

    assert result.cvss[0].score == 10.0


def test_rounding():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 9.84,
        }
    )

    assert result.cvss[0].score == 9.8


def test_cvss_score_alias():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss_score": 8.5,
        }
    )

    assert result.cvss[0].score == 8.5


def test_cvss_v3_score_alias():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss_v3_score": 9.8,
        }
    )

    assert result.cvss[0].score == 9.8


def test_cvss_v2_score_alias():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss_v2_score": 6.4,
        }
    )

    assert result.cvss[0].score == 6.4


def test_score_alias():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "score": 5.6,
        }
    )

    assert result.cvss[0].score == 5.6


def test_field_priority():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 9.8,
            "cvss_score": 5.0,
        }
    )

    assert result.cvss[0].score == 9.8


def test_none_collection():
    result = extract_cvss(None)

    assert result.extracted is False
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.cvss == ()


def test_empty_collection():
    result = extract_cvss([])

    assert result.extracted is False
    assert result.status == "NO_VULNERABILITIES"


def test_string_collection_unsupported():
    result = extract_cvss("CVE-2026-0001")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_bytes_collection_unsupported():
    result = extract_cvss(b"CVE-2026-0001")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_integer_collection_unsupported():
    result = extract_cvss(123)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_missing_cvss():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_none_cvss():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": None,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_empty_cvss():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": " ",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_invalid_cvss_string():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": "high",
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_negative_score():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": -0.1,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_score_above_ten():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 10.1,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_boolean_score_invalid():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": True,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_non_numeric_object_invalid():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": object(),
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_CVSS"


def test_missing_identifier():
    result = extract_single_cvss(
        {
            "cvss": 9.8,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_empty_identifier():
    result = extract_single_cvss(
        {
            "id": " ",
            "cvss": 9.8,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_bytes_identifier_invalid():
    result = extract_single_cvss(
        {
            "id": b"CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_identifier_normalization():
    result = extract_single_cvss(
        {
            "id": "  cve-2026-0001  ",
            "cvss": 9.8,
        }
    )

    assert result.cvss[0].identifier == "CVE-2026-0001"


def test_vulnerability_id_alias():
    result = extract_single_cvss(
        {
            "vulnerability_id": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert result.cvss[0].identifier == "CVE-2026-0001"


def test_vuln_id_alias():
    result = extract_single_cvss(
        {
            "vuln_id": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert result.cvss[0].identifier == "CVE-2026-0001"


def test_cve_alias():
    result = extract_single_cvss(
        {
            "cve": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert result.cvss[0].identifier == "CVE-2026-0001"


def test_ghsa_alias():
    result = extract_single_cvss(
        {
            "ghsa": "GHSA-AAAA-BBBB-CCCC",
            "cvss": 7.5,
        }
    )

    assert result.cvss[0].identifier == "GHSA-AAAA-BBBB-CCCC"


def test_multiple_vulnerabilities():
    result = extract_cvss(
        [
            {"id": "CVE-2026-0003", "cvss": 4.3},
            {"id": "CVE-2026-0001", "cvss": 9.8},
            {"id": "CVE-2026-0002", "cvss": 7.5},
        ]
    )

    assert result.cvss == (
        CVSS("CVE-2026-0001", 9.8),
        CVSS("CVE-2026-0002", 7.5),
        CVSS("CVE-2026-0003", 4.3),
    )


def test_duplicates_are_deduplicated():
    result = extract_cvss(
        [
            {"id": "CVE-2026-0001", "cvss": 9.8},
            {"id": "CVE-2026-0001", "cvss": 9.8},
        ]
    )

    assert result.cvss == (
        CVSS("CVE-2026-0001", 9.8),
    )


def test_deterministic_result():
    vulnerabilities = [
        {"id": "CVE-2026-0002", "cvss": 7.5},
        {"id": "CVE-2026-0001", "cvss": 9.8},
    ]

    first = extract_cvss(vulnerabilities)
    second = extract_cvss(vulnerabilities)

    assert first == second


def test_dict_as_single_vulnerability():
    result = extract_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert result.extracted is True
    assert result.cvss == (
        CVSS("CVE-2026-0001", 9.8),
    )


def test_object_input():
    class Vulnerability:
        identifier = "CVE-2026-0001"
        cvss = 8.8

    result = extract_single_cvss(Vulnerability())

    assert result.cvss == (
        CVSS("CVE-2026-0001", 8.8),
    )


def test_result_is_frozen():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    try:
        result.extracted = False
        assert False
    except FrozenInstanceError:
        pass


def test_cvss_is_frozen():
    value = CVSS("CVE-2026-0001", 9.8)

    try:
        value.score = 5.0
        assert False
    except FrozenInstanceError:
        pass


def test_result_type():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert isinstance(result, CVSSExtractionResult)


def test_cvss_type():
    result = extract_single_cvss(
        {
            "id": "CVE-2026-0001",
            "cvss": 9.8,
        }
    )

    assert isinstance(result.cvss[0], CVSS)
