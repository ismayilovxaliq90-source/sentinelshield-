from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from sentinelshield.informational_classification import (
    InformationalVulnerability,
    InformationalClassificationResult,
    classify_informational_severity,
    informational_classification,
)


def test_none():
    result = classify_informational_severity(None)
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.classified is False
    assert result.vulnerabilities == ()


@pytest.mark.parametrize("value", ["CVE-1", b"CVE-1", 123, object()])
def test_unsupported_collection(value):
    result = classify_informational_severity(value)
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"
    assert result.classified is False


def test_empty():
    result = classify_informational_severity([])
    assert result.status == "NO_VULNERABILITIES"
    assert result.classified is False


def test_informational():
    result = classify_informational_severity(
        [{"identifier": "cve-2026-0001", "severity": "informational"}]
    )
    assert result.status == "INFORMATIONAL_VULNERABILITIES_CLASSIFIED"
    assert result.classified is True
    assert result.vulnerabilities == (
        InformationalVulnerability("CVE-2026-0001"),
    )


def test_info_alias():
    result = classify_informational_severity(
        [{"id": "CVE-2026-0002", "severity": "INFO"}]
    )
    assert result.vulnerabilities[0].severity == "INFORMATIONAL"


def test_non_informational_excluded():
    result = classify_informational_severity(
        [
            {"identifier": "CVE-1", "severity": "CRITICAL"},
            {"identifier": "CVE-2", "severity": "HIGH"},
            {"identifier": "CVE-3", "severity": "MEDIUM"},
            {"identifier": "CVE-4", "severity": "LOW"},
        ]
    )
    assert result.status == "NO_INFORMATIONAL_VULNERABILITIES"
    assert result.vulnerabilities == ()


def test_unknown_is_not_informational():
    result = classify_informational_severity(
        [{"identifier": "CVE-1", "severity": "UNKNOWN"}]
    )
    assert result.status == "NO_INFORMATIONAL_VULNERABILITIES"


def test_missing_identifier():
    result = classify_informational_severity(
        [{"severity": "INFO"}]
    )
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_empty_identifier():
    result = classify_informational_severity(
        [{"identifier": "   ", "severity": "INFO"}]
    )
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_invalid_identifier_type():
    result = classify_informational_severity(
        [{"identifier": 123, "severity": "INFO"}]
    )
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_missing_severity():
    result = classify_informational_severity(
        [{"identifier": "CVE-1"}]
    )
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


def test_invalid_severity():
    result = classify_informational_severity(
        [{"identifier": "CVE-1", "severity": "NOT_A_SEVERITY"}]
    )
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


def test_invalid_severity_type():
    result = classify_informational_severity(
        [{"identifier": "CVE-1", "severity": 1}]
    )
    assert result.status == "INVALID_VULNERABILITY_SEVERITY"


def test_package_normalization():
    result = classify_informational_severity(
        [
            {
                "identifier": "cve-1",
                "severity": "INFO",
                "package_name": " My_Package.Name ",
            }
        ]
    )
    assert result.vulnerabilities[0].package_name == "my-package-name"


def test_empty_package_becomes_none():
    result = classify_informational_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "INFO",
                "package_name": "   ",
            }
        ]
    )
    assert result.vulnerabilities[0].package_name is None


def test_invalid_package():
    result = classify_informational_severity(
        [
            {
                "identifier": "CVE-1",
                "severity": "INFO",
                "package_name": 123,
            }
        ]
    )
    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_object_record():
    record = SimpleNamespace(
        identifier="cve-2",
        severity="INFO",
        package_name="Example_Package",
    )
    result = classify_informational_severity([record])
    assert result.vulnerabilities == (
        InformationalVulnerability(
            "CVE-2",
            "example-package",
        ),
    )


def test_mapping_single_record():
    result = classify_informational_severity(
        {"identifier": "CVE-3", "severity": "INFO"}
    )
    assert result.classified is True


def test_field_aliases():
    result = classify_informational_severity(
        [
            {
                "cve": "cve-4",
                "severity_level": "INFO",
                "package": "foo_bar",
            }
        ]
    )
    assert result.vulnerabilities == (
        InformationalVulnerability("CVE-4", "foo-bar"),
    )


def test_duplicate_records_are_deduplicated():
    result = classify_informational_severity(
        [
            {"identifier": "CVE-5", "severity": "INFO"},
            {"identifier": "CVE-5", "severity": "INFORMATIONAL"},
            {"identifier": "CVE-5", "severity": "INFO"},
        ]
    )
    assert len(result.vulnerabilities) == 1


def test_same_identifier_different_packages_preserved():
    result = classify_informational_severity(
        [
            {"identifier": "CVE-6", "severity": "INFO", "package": "a"},
            {"identifier": "CVE-6", "severity": "INFO", "package": "b"},
        ]
    )
    assert len(result.vulnerabilities) == 2


def test_deterministic_sorting():
    result = classify_informational_severity(
        [
            {"identifier": "CVE-9", "severity": "INFO"},
            {"identifier": "CVE-1", "severity": "INFO"},
            {"identifier": "CVE-5", "severity": "INFO"},
        ]
    )
    assert [item.identifier for item in result.vulnerabilities] == [
        "CVE-1",
        "CVE-5",
        "CVE-9",
    ]


def test_identifier_is_normalized():
    result = classify_informational_severity(
        [{"identifier": "  cve-10  ", "severity": "  info  "}]
    )
    assert result.vulnerabilities[0].identifier == "CVE-10"


def test_result_is_immutable():
    result = classify_informational_severity(
        [{"identifier": "CVE-11", "severity": "INFO"}]
    )
    with pytest.raises(FrozenInstanceError):
        result.classified = False


def test_item_is_immutable():
    item = InformationalVulnerability("CVE-12")
    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-13"


def test_alias_function():
    direct = classify_informational_severity(
        [{"identifier": "CVE-13", "severity": "INFO"}]
    )
    alias = informational_classification(
        [{"identifier": "CVE-13", "severity": "INFO"}]
    )
    assert alias == direct


def test_result_type():
    result = classify_informational_severity(
        [{"identifier": "CVE-14", "severity": "INFO"}]
    )
    assert isinstance(result, InformationalClassificationResult)


def test_item_type():
    result = classify_informational_severity(
        [{"identifier": "CVE-15", "severity": "INFO"}]
    )
    assert isinstance(result.vulnerabilities[0], InformationalVulnerability)


def test_tuple_input():
    result = classify_informational_severity(
        (
            {"identifier": "CVE-16", "severity": "INFO"},
        )
    )
    assert result.classified is True
