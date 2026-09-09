from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.medium_severity_classification import (
    MediumSeverityClassificationResult,
    MediumVulnerability,
    classify_medium_severity,
    medium_severity_classification,
)


def test_basic_medium_classification():
    result = classify_medium_severity(
        [
            {"identifier": "cve-2026-0002", "severity": "MEDIUM"},
            {"identifier": "cve-2026-0001", "severity": "HIGH"},
        ]
    )

    assert result.classified is True
    assert result.status == "MEDIUM_VULNERABILITIES_CLASSIFIED"
    assert result.vulnerabilities == (
        MediumVulnerability("CVE-2026-0002"),
    )


@pytest.mark.parametrize(
    "severity",
    ["MEDIUM", "medium", " MEDIUM ", "MED", "MODERATE"],
)
def test_medium_aliases(severity):
    result = classify_medium_severity(
        [{"identifier": "cve-1", "severity": severity}]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1"),
    )


@pytest.mark.parametrize(
    "severity",
    [
        "CRITICAL",
        "CRIT",
        "HIGH",
        "LOW",
        "INFORMATIONAL",
        "UNKNOWN",
    ],
)
def test_non_medium_severities_are_excluded(severity):
    result = classify_medium_severity(
        [
            {"identifier": "cve-1", "severity": severity},
            {"identifier": "cve-2", "severity": "MEDIUM"},
        ]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-2"),
    )


def test_no_medium_vulnerabilities():
    result = classify_medium_severity(
        [{"identifier": "CVE-1", "severity": "HIGH"}]
    )

    assert result.classified is True
    assert result.status == "NO_MEDIUM_VULNERABILITIES"
    assert result.vulnerabilities == ()


def test_identifier_normalization():
    result = classify_medium_severity(
        [{"identifier": "  cve-2026-1234  ", "severity": "medium"}]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-2026-1234"),
    )


def test_package_normalization():
    result = classify_medium_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "MEDIUM",
                "package": " My_Package.Name ",
            }
        ]
    )

    assert result.vulnerabilities == (
        MediumVulnerability(
            "CVE-1",
            "my-package-name",
        ),
    )


def test_none():
    result = classify_medium_severity(None)

    assert result.classified is False
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.vulnerabilities == ()


@pytest.mark.parametrize(
    "value",
    ["CVE-1", b"CVE-1", bytearray(b"CVE-1"), 123],
)
def test_unsupported_collection(value):
    result = classify_medium_severity(value)

    assert result.classified is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_empty_collection():
    result = classify_medium_severity([])

    assert result.classified is False
    assert result.status == "NO_VULNERABILITIES"


def test_dict_is_single_record():
    result = classify_medium_severity(
        {
            "identifier": "cve-1",
            "severity": "medium",
            "package": "Demo",
        }
    )

    assert result.classified is True
    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1", "demo"),
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
    result = classify_medium_severity(
        [{field: "cve-2026-1", "severity": "MEDIUM"}]
    )

    assert result.vulnerabilities[0].identifier == "CVE-2026-1"


@pytest.mark.parametrize(
    "field",
    ["severity", "severity_level", "severity_rating"],
)
def test_severity_aliases(field):
    result = classify_medium_severity(
        [{"identifier": "CVE-1", field: "MEDIUM"}]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1"),
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
    result = classify_medium_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "MEDIUM",
                field: "Demo_Package",
            }
        ]
    )

    assert result.vulnerabilities[0].package_name == "demo-package"


def test_missing_identifier():
    result = classify_medium_severity(
        [{"severity": "MEDIUM"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_RECORD"


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", b"CVE-1", 123],
)
def test_invalid_identifier(value):
    result = classify_medium_severity(
        [{"identifier": value, "severity": "MEDIUM"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_missing_severity():
    result = classify_medium_severity(
        [{"identifier": "CVE-1"}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", b"MEDIUM", 123],
)
def test_invalid_severity(value):
    result = classify_medium_severity(
        [{"identifier": "CVE-1", "severity": value}]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


def test_invalid_package_type():
    result = classify_medium_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "MEDIUM",
                "package": 123,
            }
        ]
    )

    assert result.classified is False
    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_empty_package_becomes_none():
    result = classify_medium_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "MEDIUM",
                "package": "   ",
            }
        ]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1", None),
    )


def test_package_optional():
    result = classify_medium_severity(
        [{"identifier": "CVE-1", "severity": "MEDIUM"}]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1", None),
    )


def test_duplicates_are_removed():
    result = classify_medium_severity(
        [
            {"identifier": "cve-1", "severity": "MEDIUM", "package": "Demo"},
            {"identifier": "CVE-1", "severity": "MED", "package": "demo"},
            {
                "identifier": "CVE-1",
                "severity": "MODERATE",
                "package": "DEMO",
            },
        ]
    )

    assert len(result.vulnerabilities) == 1


def test_same_identifier_different_packages_are_preserved():
    result = classify_medium_severity(
        [
            {"identifier": "CVE-1", "severity": "MEDIUM", "package": "alpha"},
            {"identifier": "CVE-1", "severity": "MEDIUM", "package": "beta"},
        ]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1", "alpha"),
        MediumVulnerability("CVE-1", "beta"),
    )


def test_deterministic_sorting():
    result = classify_medium_severity(
        [
            {"identifier": "CVE-3", "severity": "MEDIUM", "package": "z"},
            {"identifier": "CVE-1", "severity": "MEDIUM", "package": "b"},
            {"identifier": "CVE-2", "severity": "MEDIUM", "package": "a"},
            {"identifier": "CVE-1", "severity": "MEDIUM", "package": "a"},
        ]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1", "a"),
        MediumVulnerability("CVE-1", "b"),
        MediumVulnerability("CVE-2", "a"),
        MediumVulnerability("CVE-3", "z"),
    )


def test_object_input():
    class Vulnerability:
        identifier = "cve-10"
        severity = "medium"
        package_name = "Demo"

    result = classify_medium_severity([Vulnerability()])

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-10", "demo"),
    )


def test_input_is_not_mutated():
    source = [
        {
            "identifier": " cve-2 ",
            "severity": "MEDIUM",
            "package": "Demo",
        },
        {
            "identifier": "cve-1",
            "severity": "LOW",
            "package": "Other",
        },
    ]
    original = [dict(item) for item in source]

    classify_medium_severity(source)

    assert source == original


def test_result_is_immutable():
    result = classify_medium_severity(
        [{"identifier": "CVE-1", "severity": "MEDIUM"}]
    )

    with pytest.raises(FrozenInstanceError):
        result.classified = False


def test_item_is_immutable():
    item = MediumVulnerability("CVE-1")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-2"


def test_result_types():
    result = medium_severity_classification(
        [{"identifier": "CVE-1", "severity": "MEDIUM"}]
    )

    assert isinstance(result, MediumSeverityClassificationResult)
    assert isinstance(
        result.vulnerabilities[0],
        MediumVulnerability,
    )


def test_extra_metadata_is_ignored():
    result = classify_medium_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "MEDIUM",
                "cvss": 5.5,
                "cwe": "CWE-79",
                "exploitability": True,
            }
        ]
    )

    assert result.vulnerabilities == (
        MediumVulnerability("CVE-1"),
    )
