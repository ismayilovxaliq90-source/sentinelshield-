from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from sentinelshield.production_exposure_assessment import (
    ProductionExposureAssessment,
    ProductionExposureAssessmentResult,
    assess_production_exposure,
    production_exposure_assessment,
)


def test_none():
    result = assess_production_exposure(None)
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.assessed is False
    assert result.assessments == ()


@pytest.mark.parametrize("value", ["CVE-1", b"CVE-1", 123, object()])
def test_unsupported_collection(value):
    result = assess_production_exposure(value)
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"
    assert result.assessed is False


def test_empty():
    result = assess_production_exposure([])
    assert result.status == "NO_VULNERABILITIES"
    assert result.assessed is False


def test_exposed_true():
    result = assess_production_exposure(
        [{"identifier": "CVE-1", "production_exposed": True}]
    )
    assert result.status == "PRODUCTION_EXPOSURE_ASSESSED"
    assert result.assessed is True
    assert result.assessments[0].exposed is True
    assert result.assessments[0].status == "EXPOSED"


def test_exposed_false():
    result = assess_production_exposure(
        [{"identifier": "CVE-2", "production_exposed": False}]
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
        ("active", True),
        ("false", False),
        ("no", False),
        ("n", False),
        ("0", False),
        ("not exposed", False),
        ("unexposed", False),
        ("inactive", False),
    ],
)
def test_exposure_aliases(value, expected):
    result = assess_production_exposure(
        [{"identifier": "CVE-3", "production_exposure": value}]
    )
    assert result.assessments[0].exposed is expected


def test_integer_boolean_values():
    true_result = assess_production_exposure(
        [{"identifier": "CVE-4", "production_exposed": 1}]
    )
    false_result = assess_production_exposure(
        [{"identifier": "CVE-5", "production_exposed": 0}]
    )

    assert true_result.assessments[0].exposed is True
    assert false_result.assessments[0].exposed is False


def test_missing_metadata_is_unknown():
    result = assess_production_exposure(
        [{"identifier": "CVE-6"}]
    )

    item = result.assessments[0]

    assert item.exposed is None
    assert item.status == "UNKNOWN"


def test_invalid_metadata():
    result = assess_production_exposure(
        [{"identifier": "CVE-7", "production_exposed": "maybe"}]
    )

    assert result.status == "INVALID_PRODUCTION_EXPOSURE_METADATA"
    assert result.assessed is False


@pytest.mark.parametrize(
    "value",
    [2, -1, object(), b"true"],
)
def test_invalid_metadata_types(value):
    result = assess_production_exposure(
        [{"identifier": "CVE-8", "production_exposed": value}]
    )
    assert result.status == "INVALID_PRODUCTION_EXPOSURE_METADATA"


def test_identifier_required():
    result = assess_production_exposure(
        [{"production_exposed": True}]
    )
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_empty_identifier():
    result = assess_production_exposure(
        [{"identifier": "   ", "production_exposed": True}]
    )
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_identifier_normalization():
    result = assess_production_exposure(
        [{"identifier": " cve-9 ", "production_exposed": True}]
    )
    assert result.assessments[0].identifier == "CVE-9"


def test_package_normalization():
    result = assess_production_exposure(
        [{
            "identifier": "CVE-10",
            "package_name": " My_Package.Name ",
            "production_exposed": True,
        }]
    )
    assert result.assessments[0].package_name == "my-package-name"


def test_empty_package_becomes_none():
    result = assess_production_exposure(
        [{
            "identifier": "CVE-11",
            "package_name": "   ",
            "production_exposed": True,
        }]
    )
    assert result.assessments[0].package_name is None


def test_invalid_package():
    result = assess_production_exposure(
        [{
            "identifier": "CVE-12",
            "package_name": 123,
            "production_exposed": True,
        }]
    )
    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_object_record():
    record = SimpleNamespace(
        identifier="cve-13",
        package_name="foo_bar",
        production_exposure=True,
    )

    result = assess_production_exposure([record])

    assert result.assessments == (
        ProductionExposureAssessment(
            "CVE-13",
            "foo-bar",
            True,
            "EXPOSED",
        ),
    )


def test_single_mapping():
    result = assess_production_exposure(
        {
            "identifier": "CVE-14",
            "production_exposed": True,
        }
    )
    assert result.assessed is True


def test_field_aliases():
    result = assess_production_exposure(
        [{
            "cve": "cve-15",
            "dependency_name": "foo_bar",
            "exposed_in_production": True,
        }]
    )

    assert result.assessments == (
        ProductionExposureAssessment(
            "CVE-15",
            "foo-bar",
            True,
            "EXPOSED",
        ),
    )


def test_production_alias():
    result = assess_production_exposure(
        [{
            "identifier": "CVE-16",
            "production": "exposed",
        }]
    )

    assert result.assessments[0].status == "EXPOSED"


def test_production_status_alias():
    result = assess_production_exposure(
        [{
            "identifier": "CVE-17",
            "production_exposure_status": "not exposed",
        }]
    )

    assert result.assessments[0].status == "NOT_EXPOSED"


def test_duplicate_records_deduplicated():
    result = assess_production_exposure(
        [
            {"identifier": "CVE-18", "production_exposed": True},
            {"identifier": "CVE-18", "production_exposed": True},
            {"identifier": "CVE-18", "production_exposed": True},
        ]
    )

    assert len(result.assessments) == 1


def test_same_identifier_different_packages_preserved():
    result = assess_production_exposure(
        [
            {
                "identifier": "CVE-19",
                "package": "alpha",
                "production_exposed": True,
            },
            {
                "identifier": "CVE-19",
                "package": "beta",
                "production_exposed": False,
            },
        ]
    )

    assert len(result.assessments) == 2


def test_deterministic_sorting():
    result = assess_production_exposure(
        [
            {"identifier": "CVE-9", "production_exposed": True},
            {"identifier": "CVE-1", "production_exposed": True},
            {"identifier": "CVE-5", "production_exposed": True},
        ]
    )

    assert [item.identifier for item in result.assessments] == [
        "CVE-1",
        "CVE-5",
        "CVE-9",
    ]


def test_field_priority():
    result = assess_production_exposure(
        [{
            "identifier": "CVE-20",
            "production_exposed": True,
            "production_exposure": False,
        }]
    )

    assert result.assessments[0].exposed is True


def test_result_immutable():
    result = assess_production_exposure(
        [{"identifier": "CVE-21", "production_exposed": True}]
    )

    with pytest.raises(FrozenInstanceError):
        result.assessed = False


def test_item_immutable():
    item = ProductionExposureAssessment("CVE-22")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-23"


def test_result_type():
    result = assess_production_exposure(
        [{"identifier": "CVE-24", "production_exposed": True}]
    )

    assert isinstance(result, ProductionExposureAssessmentResult)


def test_item_type():
    result = assess_production_exposure(
        [{"identifier": "CVE-25", "production_exposed": True}]
    )

    assert isinstance(result.assessments[0], ProductionExposureAssessment)


def test_alias_function():
    data = [{"identifier": "CVE-26", "production_exposed": True}]

    assert production_exposure_assessment(data) == assess_production_exposure(data)


def test_tuple_input():
    result = assess_production_exposure(
        ({"identifier": "CVE-27", "production_exposed": True},)
    )

    assert result.assessed is True


def test_multiple_records():
    result = assess_production_exposure(
        [
            {"identifier": "CVE-28", "production_exposed": True},
            {"identifier": "CVE-29", "production_exposed": False},
            {"identifier": "CVE-30"},
        ]
    )

    assert [item.status for item in result.assessments] == [
        "EXPOSED",
        "NOT_EXPOSED",
        "UNKNOWN",
    ]
