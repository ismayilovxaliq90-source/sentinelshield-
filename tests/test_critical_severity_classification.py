from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.critical_severity_classification import (
    CriticalSeverityClassificationResult,
    CriticalVulnerability,
    classify_critical_severity,
    critical_severity_classification,
)


def test_basic_critical_classification():
    result = classify_critical_severity(
        [
            {"identifier": "cve-2026-0002", "severity": "CRITICAL"},
            {"identifier": "cve-2026-0001", "severity": "HIGH"},
        ]
    )

    assert result.classified is True
    assert result.status == "CRITICAL_VULNERABILITIES_CLASSIFIED"
    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-2026-0002"),
    )


@pytest.mark.parametrize(
    "severity",
    ["CRITICAL", "critical", " CRITICAL ", "CRIT", "criticality"],
)
def test_critical_aliases(severity):
    result = classify_critical_severity(
        [{"identifier": "cve-1", "severity": severity}]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-1"),
    )


@pytest.mark.parametrize(
    "severity",
    ["HIGH", "MEDIUM", "MODERATE", "LOW", "INFORMATIONAL", "UNKNOWN"],
)
def test_non_critical_severities_are_excluded(severity):
    result = classify_critical_severity(
        [
            {"identifier": "cve-1", "severity": severity},
            {"identifier": "cve-2", "severity": "CRITICAL"},
        ]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-2"),
    )


def test_no_critical_vulnerabilities():
    result = classify_critical_severity(
        [{"identifier": "CVE-1", "severity": "HIGH"}]
    )

    assert result.classified is True
    assert result.status == "NO_CRITICAL_VULNERABILITIES"
    assert result.vulnerabilities == ()


def test_identifier_normalization():
    result = classify_critical_severity(
        [{"identifier": "  cve-2026-1234  ", "severity": "critical"}]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-2026-1234"),
    )


def test_package_normalization():
    result = classify_critical_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "CRITICAL",
                "package": " My_Package.Name ",
            }
        ]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability(
            "CVE-1",
            "my-package-name",
        ),
    )


def test_none():
    result = classify_critical_severity(None)

    assert result.classified is False
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.vulnerabilities == ()


@pytest.mark.parametrize(
    "value",
    ["CVE-1", b"CVE-1", bytearray(b"CVE-1"), 123],
)
def test_unsupported_collection(value):
    result = classify_critical_severity(value)

    assert result.classified is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_empty_collection():
    result = classify_critical_severity([])

    assert result.classified is False
    assert result.status == "NO_VULNERABILITIES"


def test_dict_is_single_record():
    result = classify_critical_severity(
        {
            "identifier": "cve-1",
            "severity": "critical",
            "package": "Demo",
        }
    )

    assert result.classified is True
    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-1", "demo"),
    )


@pytest.mark.parametrize(
    "field",
    [
        "identifier",
        "id",
        "vulnerability_id",
        "vuln_id",
        "cve",
        "ghsa",
    ],
)
def test_identifier_aliases(field):
    result = classify_critical_severity(
        [{field: "cve-2026-1", "severity": "critical"}]
    )

    assert result.vulnerabilities[0].identifier == "CVE-2026-1"


@pytest.mark.parametrize(
    "field",
    ["severity", "severity_level", "severity_rating"],
)
def test_severity_aliases(field):
    result = classify_critical_severity(
        [{"identifier": "CVE-1", field: "critical"}]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-1"),
    )


@pytest.mark.parametrize(
    "field",
    [
        "package",
        "package_name",
        "dependency",
        "dependency_name",
        "affected_package",
        "affected_package_name",
    ],
)
def test_package_aliases(field):
    result = classify_critical_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "critical",
                field: "Demo_Package",
            }
        ]
    )

    assert result.vulnerabilities[0].package_name == "demo-package"


def test_missing_identifier():
    result = classify_critical_severity(
        [{"severity": "critical"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_RECORD"


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", b"CVE-1", 123],
)
def test_invalid_identifier(value):
    result = classify_critical_severity(
        [{"identifier": value, "severity": "critical"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_missing_severity():
    result = classify_critical_severity(
        [{"identifier": "CVE-1"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", b"CRITICAL", 123],
)
def test_invalid_severity(value):
    result = classify_critical_severity(
        [{"identifier": "CVE-1", "severity": value}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


def test_invalid_package_type():
    result = classify_critical_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "critical",
                "package": 123,
            }
        ]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_empty_package_becomes_none():
    result = classify_critical_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "critical",
                "package": "   ",
            }
        ]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-1", None),
    )


def test_duplicates_are_removed():
    result = classify_critical_severity(
        [
            {"identifier": "cve-1", "severity": "critical", "package": "Demo"},
            {"identifier": "CVE-1", "severity": "CRIT", "package": "demo"},
            {"identifier": "CVE-1", "severity": "CRITICAL", "package": "DEMO"},
        ]
    )

    assert len(result.vulnerabilities) == 1


def test_same_identifier_different_packages_are_preserved():
    result = classify_critical_severity(
        [
            {"identifier": "CVE-1", "severity": "critical", "package": "alpha"},
            {"identifier": "CVE-1", "severity": "critical", "package": "beta"},
        ]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-1", "alpha"),
        CriticalVulnerability("CVE-1", "beta"),
    )


def test_deterministic_sorting():
    result = classify_critical_severity(
        [
            {"identifier": "CVE-3", "severity": "critical", "package": "z"},
            {"identifier": "CVE-1", "severity": "critical", "package": "b"},
            {"identifier": "CVE-2", "severity": "critical", "package": "a"},
            {"identifier": "CVE-1", "severity": "critical", "package": "a"},
        ]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-1", "a"),
        CriticalVulnerability("CVE-1", "b"),
        CriticalVulnerability("CVE-2", "a"),
        CriticalVulnerability("CVE-3", "z"),
    )


def test_object_input():
    class Vulnerability:
        identifier = "cve-10"
        severity = "critical"
        package_name = "Demo"

    result = classify_critical_severity([Vulnerability()])

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-10", "demo"),
    )


def test_input_is_not_mutated():
    source = [
        {
            "identifier": " cve-2 ",
            "severity": "critical",
            "package": "Demo",
        },
        {
            "identifier": "cve-1",
            "severity": "high",
            "package": "Other",
        },
    ]
    original = [dict(item) for item in source]

    classify_critical_severity(source)

    assert source == original


def test_result_is_immutable():
    result = classify_critical_severity(
        [{"identifier": "CVE-1", "severity": "critical"}]
    )

    with pytest.raises(FrozenInstanceError):
        result.classified = False


def test_item_is_immutable():
    item = CriticalVulnerability("CVE-1")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-2"


def test_result_types():
    result = critical_severity_classification(
        [{"identifier": "CVE-1", "severity": "critical"}]
    )

    assert isinstance(result, CriticalSeverityClassificationResult)
    assert isinstance(
        result.vulnerabilities[0],
        CriticalVulnerability,
    )


def test_extra_metadata_is_ignored():
    result = classify_critical_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "critical",
                "cvss": 9.8,
                "cwe": "CWE-79",
                "exploitability": True,
            }
        ]
    )

    assert result.vulnerabilities == (
        CriticalVulnerability("CVE-1"),
    )
