from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.severity_extraction import (
    Severity,
    SeverityExtractionResult,
    extract_severities,
    extract_severity,
)


def test_critical():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "critical"}
    )

    assert result.extracted is True
    assert result.status == "SEVERITIES_EXTRACTED"
    assert result.severities == (
        Severity("CVE-2026-0001", "CRITICAL"),
    )


def test_critical_alias():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "crit"}
    )

    assert result.severities[0].severity == "CRITICAL"


def test_criticality_alias():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "criticality"}
    )

    assert result.severities[0].severity == "CRITICAL"


def test_high():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "high"}
    )

    assert result.severities[0].severity == "HIGH"


def test_medium():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "medium"}
    )

    assert result.severities[0].severity == "MEDIUM"


def test_medium_alias():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "med"}
    )

    assert result.severities[0].severity == "MEDIUM"


def test_moderate_alias():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "moderate"}
    )

    assert result.severities[0].severity == "MEDIUM"


def test_low():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "low"}
    )

    assert result.severities[0].severity == "LOW"


def test_informational():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "informational"}
    )

    assert result.severities[0].severity == "INFORMATIONAL"


def test_info_alias():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "info"}
    )

    assert result.severities[0].severity == "INFORMATIONAL"


def test_unknown():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "unknown"}
    )

    assert result.severities[0].severity == "UNKNOWN"


def test_whitespace_is_normalized():
    result = extract_severity(
        {"id": "  cve-2026-0001  ", "severity": "  HIGH  "}
    )

    assert result.severities == (
        Severity("CVE-2026-0001", "HIGH"),
    )


def test_identifier_field_priority():
    result = extract_severity(
        {
            "severity": "high",
            "identifier": "CVE-2026-0001",
            "id": "CVE-2026-0002",
        }
    )

    assert result.severities[0].identifier == "CVE-2026-0001"


def test_severity_field_priority():
    result = extract_severity(
        {
            "id": "CVE-2026-0001",
            "severity": "high",
            "severity_level": "low",
        }
    )

    assert result.severities[0].severity == "HIGH"


def test_vulnerability_id_alias():
    result = extract_severity(
        {
            "vulnerability_id": "CVE-2026-0001",
            "severity": "high",
        }
    )

    assert result.severities[0].identifier == "CVE-2026-0001"


def test_vuln_id_alias():
    result = extract_severity(
        {
            "vuln_id": "CVE-2026-0001",
            "severity": "high",
        }
    )

    assert result.severities[0].identifier == "CVE-2026-0001"


def test_cve_alias():
    result = extract_severity(
        {
            "cve": "CVE-2026-0001",
            "severity": "high",
        }
    )

    assert result.severities[0].identifier == "CVE-2026-0001"


def test_ghsa_alias():
    result = extract_severity(
        {
            "ghsa": "GHSA-AAAA-BBBB-CCCC",
            "severity": "high",
        }
    )

    assert result.severities[0].identifier == "GHSA-AAAA-BBBB-CCCC"


def test_none_collection():
    result = extract_severities(None)

    assert result.extracted is False
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.severities == ()


def test_empty_collection():
    result = extract_severities([])

    assert result.extracted is False
    assert result.status == "NO_VULNERABILITIES"


def test_string_collection_is_unsupported():
    result = extract_severities("CVE-2026-0001")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_bytes_collection_is_unsupported():
    result = extract_severities(b"CVE-2026-0001")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_integer_collection_is_unsupported():
    result = extract_severities(123)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_missing_severity():
    result = extract_severity(
        {"id": "CVE-2026-0001"}
    )

    assert result.extracted is False
    assert result.status == "INVALID_SEVERITY"


def test_invalid_severity():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "extreme"}
    )

    assert result.extracted is False
    assert result.status == "INVALID_SEVERITY"


def test_non_string_severity():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": 10}
    )

    assert result.extracted is False
    assert result.status == "INVALID_SEVERITY"


def test_missing_identifier():
    result = extract_severity(
        {"severity": "high"}
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_empty_identifier():
    result = extract_severity(
        {"id": "   ", "severity": "high"}
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_bytes_identifier_is_invalid():
    result = extract_severity(
        {"id": b"CVE-2026-0001", "severity": "high"}
    )

    assert result.extracted is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_duplicate_entries_are_deduplicated():
    vulnerabilities = [
        {"id": "CVE-2026-0001", "severity": "high"},
        {"id": "CVE-2026-0001", "severity": "HIGH"},
    ]

    result = extract_severities(vulnerabilities)

    assert result.severities == (
        Severity("CVE-2026-0001", "HIGH"),
    )


def test_multiple_vulnerabilities():
    vulnerabilities = [
        {"id": "CVE-2026-0003", "severity": "low"},
        {"id": "CVE-2026-0001", "severity": "critical"},
        {"id": "CVE-2026-0002", "severity": "medium"},
    ]

    result = extract_severities(vulnerabilities)

    assert result.severities == (
        Severity("CVE-2026-0001", "CRITICAL"),
        Severity("CVE-2026-0002", "MEDIUM"),
        Severity("CVE-2026-0003", "LOW"),
    )


def test_deterministic_order():
    vulnerabilities = [
        {"id": "CVE-2026-0002", "severity": "high"},
        {"id": "CVE-2026-0001", "severity": "low"},
    ]

    first = extract_severities(vulnerabilities)
    second = extract_severities(vulnerabilities)

    assert first == second


def test_result_is_frozen():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "high"}
    )

    with pytest.raises(FrozenInstanceError):
        result.extracted = False


def test_severity_is_frozen():
    severity = Severity("CVE-2026-0001", "HIGH")

    with pytest.raises(FrozenInstanceError):
        severity.severity = "LOW"


def test_object_input():
    class Vulnerability:
        identifier = "CVE-2026-0001"
        severity = "high"

    result = extract_severity(Vulnerability())

    assert result.severities == (
        Severity("CVE-2026-0001", "HIGH"),
    )


def test_severity_level_fallback():
    result = extract_severity(
        {
            "id": "CVE-2026-0001",
            "severity_level": "medium",
        }
    )

    assert result.severities[0].severity == "MEDIUM"


def test_severity_rating_fallback():
    result = extract_severity(
        {
            "id": "CVE-2026-0001",
            "severity_rating": "low",
        }
    )

    assert result.severities[0].severity == "LOW"


def test_none_severity_is_invalid():
    result = extract_severity(
        {
            "id": "CVE-2026-0001",
            "severity": None,
        }
    )

    assert result.extracted is False
    assert result.status == "INVALID_SEVERITY"


def test_dict_is_supported_as_single_vulnerability():
    result = extract_severities(
        {
            "id": "CVE-2026-0001",
            "severity": "critical",
        }
    )

    assert result.extracted is True
    assert result.severities == (
        Severity("CVE-2026-0001", "CRITICAL"),
    )


def test_tuple_collection():
    result = extract_severities(
        (
            {"id": "CVE-2026-0001", "severity": "high"},
        )
    )

    assert result.status == "SEVERITIES_EXTRACTED"


def test_result_type():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "high"}
    )

    assert isinstance(result, SeverityExtractionResult)


def test_severity_type():
    result = extract_severity(
        {"id": "CVE-2026-0001", "severity": "high"}
    )

    assert isinstance(result.severities[0], Severity)
