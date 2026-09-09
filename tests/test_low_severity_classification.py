from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.low_severity_classification import (
    LowSeverityClassificationResult,
    LowVulnerability,
    classify_low_severity,
    low_severity_classification,
)


def test_basic_low_classification():
    result = classify_low_severity(
        [
            {"identifier": "cve-2026-0002", "severity": "LOW"},
            {"identifier": "cve-2026-0001", "severity": "HIGH"},
        ]
    )

    assert result.classified is True
    assert result.status == "LOW_VULNERABILITIES_CLASSIFIED"
    assert result.vulnerabilities == (
        LowVulnerability("CVE-2026-0002"),
    )


@pytest.mark.parametrize(
    "severity",
    ["LOW", "low", " LOW "],
)
def test_low_normalization(severity):
    result = classify_low_severity(
        [{"identifier": "cve-1", "severity": severity}]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-1"),
    )


@pytest.mark.parametrize(
    "severity",
    [
        "CRITICAL",
        "CRIT",
        "HIGH",
        "MED",
        "MEDIUM",
        "MODERATE",
        "INFORMATIONAL",
        "UNKNOWN",
    ],
)
def test_non_low_severities_are_excluded(severity):
    result = classify_low_severity(
        [
            {"identifier": "cve-1", "severity": severity},
            {"identifier": "cve-2", "severity": "LOW"},
        ]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-2"),
    )


def test_no_low_vulnerabilities():
    result = classify_low_severity(
        [{"identifier": "CVE-1", "severity": "HIGH"}]
    )

    assert result.classified is True
    assert result.status == "NO_LOW_VULNERABILITIES"
    assert result.vulnerabilities == ()


def test_identifier_normalization():
    result = classify_low_severity(
        [{"identifier": "  cve-2026-1234  ", "severity": "low"}]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-2026-1234"),
    )


def test_package_normalization():
    result = classify_low_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "LOW",
                "package": " My_Package.Name ",
            }
        ]
    )

    assert result.vulnerabilities == (
        LowVulnerability(
            "CVE-1",
            "my-package-name",
        ),
    )


def test_none():
    result = classify_low_severity(None)

    assert result.classified is False
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.vulnerabilities == ()


@pytest.mark.parametrize(
    "value",
    ["CVE-1", b"CVE-1", bytearray(b"CVE-1"), 123],
)
def test_unsupported_collection(value):
    result = classify_low_severity(value)

    assert result.classified is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_empty_collection():
    result = classify_low_severity([])

    assert result.classified is False
    assert result.status == "NO_VULNERABILITIES"


def test_dict_is_single_record():
    result = classify_low_severity(
        {
            "identifier": "cve-1",
            "severity": "low",
            "package": "Demo",
        }
    )

    assert result.classified is True
    assert result.vulnerabilities == (
        LowVulnerability("CVE-1", "demo"),
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
    result = classify_low_severity(
        [{field: "cve-2026-1", "severity": "LOW"}]
    )

    assert result.vulnerabilities[0].identifier == "CVE-2026-1"


@pytest.mark.parametrize(
    "field",
    ["severity", "severity_level", "severity_rating"],
)
def test_severity_aliases(field):
    result = classify_low_severity(
        [{"identifier": "CVE-1", field: "LOW"}]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-1"),
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
    result = classify_low_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "LOW",
                field: "Demo_Package",
            }
        ]
    )

    assert result.vulnerabilities[0].package_name == "demo-package"


def test_missing_identifier():
    result = classify_low_severity(
        [{"severity": "LOW"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_RECORD"


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", b"CVE-1", 123],
)
def test_invalid_identifier(value):
    result = classify_low_severity(
        [{"identifier": value, "severity": "LOW"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_missing_severity():
    result = classify_low_severity(
        [{"identifier": "CVE-1"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", b"LOW", 123],
)
def test_invalid_severity(value):
    result = classify_low_severity(
        [{"identifier": "CVE-1", "severity": value}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


def test_invalid_package_type():
    result = classify_low_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "LOW",
                "package": 123,
            }
        ]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_empty_package_becomes_none():
    result = classify_low_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "LOW",
                "package": "   ",
            }
        ]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-1", None),
    )


def test_package_optional():
    result = classify_low_severity(
        [{"identifier": "CVE-1", "severity": "LOW"}]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-1", None),
    )


def test_duplicates_are_removed():
    result = classify_low_severity(
        [
            {"identifier": "cve-1", "severity": "LOW", "package": "Demo"},
            {"identifier": "CVE-1", "severity": "low", "package": "demo"},
            {"identifier": "CVE-1", "severity": " LOW ", "package": "DEMO"},
        ]
    )

    assert len(result.vulnerabilities) == 1


def test_same_identifier_different_packages_are_preserved():
    result = classify_low_severity(
        [
            {"identifier": "CVE-1", "severity": "LOW", "package": "alpha"},
            {"identifier": "CVE-1", "severity": "LOW", "package": "beta"},
        ]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-1", "alpha"),
        LowVulnerability("CVE-1", "beta"),
    )


def test_deterministic_sorting():
    result = classify_low_severity(
        [
            {"identifier": "CVE-3", "severity": "LOW", "package": "z"},
            {"identifier": "CVE-1", "severity": "LOW", "package": "b"},
            {"identifier": "CVE-2", "severity": "LOW", "package": "a"},
            {"identifier": "CVE-1", "severity": "LOW", "package": "a"},
        ]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-1", "a"),
        LowVulnerability("CVE-1", "b"),
        LowVulnerability("CVE-2", "a"),
        LowVulnerability("CVE-3", "z"),
    )


def test_object_input():
    class Vulnerability:
        identifier = "cve-10"
        severity = "low"
        package_name = "Demo"

    result = classify_low_severity([Vulnerability()])

    assert result.vulnerabilities == (
        LowVulnerability("CVE-10", "demo"),
    )


def test_input_is_not_mutated():
    source = [
        {
            "identifier": " cve-2 ",
            "severity": "LOW",
            "package": "Demo",
        },
        {
            "identifier": "cve-1",
            "severity": "HIGH",
            "package": "Other",
        },
    ]

    original = [dict(item) for item in source]

    classify_low_severity(source)

    assert source == original


def test_result_is_immutable():
    result = classify_low_severity(
        [{"identifier": "CVE-1", "severity": "LOW"}]
    )

    with pytest.raises(FrozenInstanceError):
        result.classified = False


def test_item_is_immutable():
    item = LowVulnerability("CVE-1")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-2"


def test_result_types():
    result = low_severity_classification(
        [{"identifier": "CVE-1", "severity": "LOW"}]
    )

    assert isinstance(result, LowSeverityClassificationResult)
    assert isinstance(
        result.vulnerabilities[0],
        LowVulnerability,
    )


def test_extra_metadata_is_ignored():
    result = classify_low_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "LOW",
                "cvss": 2.1,
                "cwe": "CWE-79",
                "exploitability": False,
            }
        ]
    )

    assert result.vulnerabilities == (
        LowVulnerability("CVE-1"),
    )
