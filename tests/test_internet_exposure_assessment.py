from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from sentinelshield.internet_exposure_assessment import (
    InternetExposureAssessment,
    InternetExposureAssessmentResult,
    assess_internet_exposure,
    internet_exposure_assessment,
)


def test_none():
    result = assess_internet_exposure(None)
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.assessed is False
    assert result.assessments == ()


@pytest.mark.parametrize("value", ["CVE-1", b"CVE-1", 123, object()])
def test_unsupported_collection(value):
    result = assess_internet_exposure(value)
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"
    assert result.assessed is False


def test_empty():
    result = assess_internet_exposure([])
    assert result.status == "NO_VULNERABILITIES"
    assert result.assessed is False


def test_exposed_true():
    result = assess_internet_exposure(
        [{"identifier": "CVE-1", "internet_exposed": True}]
    )

    assert result.status == "INTERNET_EXPOSURE_ASSESSED"
    assert result.assessed is True
    assert result.assessments[0].exposed is True
    assert result.assessments[0].status == "EXPOSED"


def test_exposed_false():
    result = assess_internet_exposure(
        [{"identifier": "CVE-2", "internet_exposed": False}]
    )

    assert result.assessments[0].exposed is False
    assert result.assessments[0].status == "NOT_EXPOSED"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("true", True),
        ("yes", True),
        ("y", True),
        ("1", True),
        ("exposed", True),
        ("internet_exposed", True),
        ("internet-exposed", True),
        ("exposed_to_internet", True),
        ("active", True),
        ("false", False),
        ("no", False),
        ("n", False),
        ("0", False),
        ("not exposed", False),
        ("not_exposed", False),
        ("not-exposed", False),
        ("unexposed", False),
        ("not exposed to internet", False),
        ("inactive", False),
    ],
)
def test_exposure_aliases(value, expected):
    result = assess_internet_exposure(
        [{"identifier": "CVE-3", "internet_exposure": value}]
    )

    assert result.assessments[0].exposed is expected


def test_integer_boolean_values():
    true_result = assess_internet_exposure(
        [{"identifier": "CVE-4", "internet_exposed": 1}]
    )
    false_result = assess_internet_exposure(
        [{"identifier": "CVE-5", "internet_exposed": 0}]
    )

    assert true_result.assessments[0].exposed is True
    assert false_result.assessments[0].exposed is False


def test_missing_metadata_is_unknown():
    result = assess_internet_exposure(
        [{"identifier": "CVE-6"}]
    )

    item = result.assessments[0]

    assert item.exposed is None
    assert item.status == "UNKNOWN"


def test_invalid_metadata():
    result = assess_internet_exposure(
        [{"identifier": "CVE-7", "internet_exposed": "maybe"}]
    )

    assert result.status == "INVALID_INTERNET_EXPOSURE_METADATA"
    assert result.assessed is False


@pytest.mark.parametrize(
    "value",
    [2, -1, object(), b"true"],
)
def test_invalid_metadata_types(value):
    result = assess_internet_exposure(
        [{"identifier": "CVE-8", "internet_exposed": value}]
    )

    assert result.status == "INVALID_INTERNET_EXPOSURE_METADATA"


def test_identifier_required():
    result = assess_internet_exposure(
        [{"internet_exposed": True}]
    )

    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_empty_identifier():
    result = assess_internet_exposure(
        [{"identifier": "   ", "internet_exposed": True}]
    )

    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_identifier_normalization():
    result = assess_internet_exposure(
        [{"identifier": " cve-9 ", "internet_exposed": True}]
    )

    assert result.assessments[0].identifier == "CVE-9"


def test_package_normalization():
    result = assess_internet_exposure(
        [{
            "identifier": "CVE-10",
            "package_name": " My_Package.Name ",
            "internet_exposed": True,
        }]
    )

    assert result.assessments[0].package_name == "my-package-name"


def test_empty_package_becomes_none():
    result = assess_internet_exposure(
        [{
            "identifier": "CVE-11",
            "package_name": "   ",
            "internet_exposed": True,
        }]
    )

    assert result.assessments[0].package_name is None


def test_invalid_package():
    result = assess_internet_exposure(
        [{
            "identifier": "CVE-12",
            "package_name": 123,
            "internet_exposed": True,
        }]
    )

    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_object_record():
    record = SimpleNamespace(
        identifier="cve-13",
        package_name="foo_bar",
        internet_exposure=True,
    )

    result = assess_internet_exposure([record])

    assert result.assessments == (
        InternetExposureAssessment(
            "CVE-13",
            "foo-bar",
            True,
            "EXPOSED",
        ),
    )


def test_single_mapping():
    result = assess_internet_exposure(
        {
            "identifier": "CVE-14",
            "internet_exposed": True,
        }
    )

    assert result.assessed is True


def test_field_aliases():
    result = assess_internet_exposure(
        [{
            "cve": "cve-15",
            "dependency_name": "foo_bar",
            "exposed_to_internet": True,
        }]
    )

    assert result.assessments == (
        InternetExposureAssessment(
            "CVE-15",
            "foo-bar",
            True,
            "EXPOSED",
        ),
    )


def test_internet_alias():
    result = assess_internet_exposure(
        [{
            "identifier": "CVE-16",
            "internet": "exposed",
        }]
    )

    assert result.assessments[0].status == "EXPOSED"


def test_internet_status_alias():
    result = assess_internet_exposure(
        [{
            "identifier": "CVE-17",
            "internet_exposure_status": "not exposed",
        }]
    )

    assert result.assessments[0].status == "NOT_EXPOSED"


def test_duplicate_records_deduplicated():
    result = assess_internet_exposure(
        [
            {"identifier": "CVE-18", "internet_exposed": True},
            {"identifier": "CVE-18", "internet_exposed": True},
            {"identifier": "CVE-18", "internet_exposed": True},
        ]
    )

    assert len(result.assessments) == 1


def test_same_identifier_different_packages_preserved():
    result = assess_internet_exposure(
        [
            {
                "identifier": "CVE-19",
                "package": "alpha",
                "internet_exposed": True,
            },
            {
                "identifier": "CVE-19",
                "package": "beta",
                "internet_exposed": False,
            },
        ]
    )

    assert len(result.assessments) == 2


def test_deterministic_sorting():
    result = assess_internet_exposure(
        [
            {"identifier": "CVE-9", "internet_exposed": True},
            {"identifier": "CVE-1", "internet_exposed": True},
            {"identifier": "CVE-5", "internet_exposed": True},
        ]
    )

    assert [item.identifier for item in result.assessments] == [
        "CVE-1",
        "CVE-5",
        "CVE-9",
    ]


def test_field_priority():
    result = assess_internet_exposure(
        [{
            "identifier": "CVE-20",
            "internet_exposed": True,
            "internet_exposure": False,
        }]
    )

    assert result.assessments[0].exposed is True


def test_result_immutable():
    result = assess_internet_exposure(
        [{"identifier": "CVE-21", "internet_exposed": True}]
    )

    with pytest.raises(FrozenInstanceError):
        result.assessed = False


def test_item_immutable():
    item = InternetExposureAssessment("CVE-22")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-23"


def test_result_type():
    result = assess_internet_exposure(
        [{"identifier": "CVE-24", "internet_exposed": True}]
    )

    assert isinstance(result, InternetExposureAssessmentResult)


def test_item_type():
    result = assess_internet_exposure(
        [{"identifier": "CVE-25", "internet_exposed": True}]
    )

    assert isinstance(
        result.assessments[0],
        InternetExposureAssessment,
    )


def test_alias_function():
    data = [{"identifier": "CVE-26", "internet_exposed": True}]

    assert internet_exposure_assessment(data) == (
        assess_internet_exposure(data)
    )


def test_tuple_input():
    result = assess_internet_exposure(
        ({"identifier": "CVE-27", "internet_exposed": True},)
    )

    assert result.assessed is True


def test_multiple_records():
    result = assess_internet_exposure(
        [
            {"identifier": "CVE-28", "internet_exposed": True},
            {"identifier": "CVE-29", "internet_exposed": False},
            {"identifier": "CVE-30"},
        ]
    )

    assert [item.status for item in result.assessments] == [
        "EXPOSED",
        "NOT_EXPOSED",
        "UNKNOWN",
    ]
