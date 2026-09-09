from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from sentinelshield.application_impact_assessment import (
    ApplicationImpactAssessment,
    ApplicationImpactAssessmentResult,
    assess_application_impact,
    application_impact_assessment,
)


def test_none():
    result = assess_application_impact(None)

    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.assessed is False
    assert result.assessments == ()


@pytest.mark.parametrize(
    "value",
    ["CVE-1", b"CVE-1", 123, object()],
)
def test_unsupported_collection(value):
    result = assess_application_impact(value)

    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"
    assert result.assessed is False


def test_empty():
    result = assess_application_impact([])

    assert result.status == "NO_VULNERABILITIES"
    assert result.assessed is False


def test_explicit_critical():
    result = assess_application_impact(
        [{"identifier": "CVE-1", "application_impact": "critical"}]
    )

    assert result.status == "APPLICATION_IMPACT_ASSESSED"
    assert result.assessed is True
    assert result.assessments[0].impact == "CRITICAL"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("CRIT", "CRITICAL"),
        ("CRITICAL", "CRITICAL"),
        ("VERY HIGH", "CRITICAL"),
        ("VERY_HIGH", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("MED", "MEDIUM"),
        ("MEDIUM", "MEDIUM"),
        ("MODERATE", "MEDIUM"),
        ("LOW", "LOW"),
        ("MINIMAL", "MINIMAL"),
        ("NONE", "MINIMAL"),
        ("INFO", "MINIMAL"),
        ("INFORMATIONAL", "MINIMAL"),
        ("UNKNOWN", "UNKNOWN"),
    ],
)
def test_impact_aliases(value, expected):
    result = assess_application_impact(
        [{"identifier": "CVE-2", "impact": value}]
    )

    assert result.assessments[0].impact == expected


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, "MINIMAL"),
        (1, "LOW"),
        (29.9, "LOW"),
        (30, "MEDIUM"),
        (59.9, "MEDIUM"),
        (60, "HIGH"),
        (79.9, "HIGH"),
        (80, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_score_boundaries(score, expected):
    result = assess_application_impact(
        [{"identifier": "CVE-3", "impact_score": score}]
    )

    assert result.assessments[0].score == float(score)
    assert result.assessments[0].impact == expected


@pytest.mark.parametrize(
    "score",
    [-1, 100.1],
)
def test_invalid_score_range(score):
    result = assess_application_impact(
        [{"identifier": "CVE-4", "impact_score": score}]
    )

    assert result.status == "INVALID_APPLICATION_IMPACT_SCORE"


def test_string_score():
    result = assess_application_impact(
        [{"identifier": "CVE-5", "impact_score": "65"}]
    )

    assert result.assessments[0].score == 65.0
    assert result.assessments[0].impact == "HIGH"


def test_missing_impact_is_unknown():
    result = assess_application_impact(
        [{"identifier": "CVE-6"}]
    )

    assert result.assessments[0].impact == "UNKNOWN"


def test_business_context():
    result = assess_application_impact(
        [{
            "identifier": "CVE-7",
            "business_impact": "high",
        }]
    )

    assert result.assessments[0].impact == "HIGH"
    assert result.assessments[0].business_impact == "HIGH"


def test_data_context():
    result = assess_application_impact(
        [{
            "identifier": "CVE-8",
            "data_impact": "critical",
        }]
    )

    assert result.assessments[0].impact == "CRITICAL"
    assert result.assessments[0].data_impact == "CRITICAL"


def test_service_context():
    result = assess_application_impact(
        [{
            "identifier": "CVE-9",
            "service_impact": "medium",
        }]
    )

    assert result.assessments[0].impact == "MEDIUM"
    assert result.assessments[0].service_impact == "MEDIUM"


def test_explicit_impact_has_priority_over_score():
    result = assess_application_impact(
        [{
            "identifier": "CVE-10",
            "application_impact": "low",
            "impact_score": 95,
        }]
    )

    assert result.assessments[0].impact == "LOW"
    assert result.assessments[0].score == 95.0


def test_explicit_impact_has_priority_over_context():
    result = assess_application_impact(
        [{
            "identifier": "CVE-11",
            "application_impact": "low",
            "business_impact": "critical",
        }]
    )

    assert result.assessments[0].impact == "LOW"


def test_identifier_required():
    result = assess_application_impact(
        [{"application_impact": "high"}]
    )

    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_identifier_normalization():
    result = assess_application_impact(
        [{"identifier": " cve-12 ", "impact": "high"}]
    )

    assert result.assessments[0].identifier == "CVE-12"


def test_package_normalization():
    result = assess_application_impact(
        [{
            "identifier": "CVE-13",
            "package_name": " My_Package.Name ",
            "impact": "high",
        }]
    )

    assert result.assessments[0].package_name == "my-package-name"


def test_empty_package():
    result = assess_application_impact(
        [{
            "identifier": "CVE-14",
            "package_name": "   ",
        }]
    )

    assert result.assessments[0].package_name is None


def test_invalid_package():
    result = assess_application_impact(
        [{
            "identifier": "CVE-15",
            "package_name": 123,
        }]
    )

    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_invalid_impact():
    result = assess_application_impact(
        [{
            "identifier": "CVE-16",
            "impact": "invalid",
        }]
    )

    assert result.status == "INVALID_APPLICATION_IMPACT_METADATA"


def test_invalid_impact_type():
    result = assess_application_impact(
        [{
            "identifier": "CVE-17",
            "impact": 123,
        }]
    )

    assert result.status == "INVALID_APPLICATION_IMPACT_METADATA"


def test_invalid_score_type():
    result = assess_application_impact(
        [{
            "identifier": "CVE-18",
            "impact_score": "not-a-number",
        }]
    )

    assert result.status == "INVALID_APPLICATION_IMPACT_SCORE"


def test_invalid_business_context():
    result = assess_application_impact(
        [{
            "identifier": "CVE-19",
            "business_impact": 123,
        }]
    )

    assert result.status == "INVALID_BUSINESS_IMPACT_METADATA"


def test_invalid_data_context():
    result = assess_application_impact(
        [{
            "identifier": "CVE-20",
            "data_impact": 123,
        }]
    )

    assert result.status == "INVALID_DATA_IMPACT_METADATA"


def test_invalid_service_context():
    result = assess_application_impact(
        [{
            "identifier": "CVE-21",
            "service_impact": 123,
        }]
    )

    assert result.status == "INVALID_SERVICE_IMPACT_METADATA"


def test_object_input():
    record = SimpleNamespace(
        identifier="cve-22",
        package_name="foo_bar",
        application_impact="high",
        business_impact="medium",
    )

    result = assess_application_impact([record])

    assert result.assessments[0] == ApplicationImpactAssessment(
        identifier="CVE-22",
        package_name="foo-bar",
        impact="HIGH",
        score=None,
        business_impact="MEDIUM",
        data_impact=None,
        service_impact=None,
    )


def test_single_mapping():
    result = assess_application_impact(
        {
            "identifier": "CVE-23",
            "impact": "medium",
        }
    )

    assert result.assessed is True


def test_field_aliases():
    result = assess_application_impact(
        [{
            "cve": "cve-24",
            "dependency_name": "foo_bar",
            "impact_level": "high",
        }]
    )

    assert result.assessments[0].identifier == "CVE-24"
    assert result.assessments[0].package_name == "foo-bar"
    assert result.assessments[0].impact == "HIGH"


def test_duplicate_records():
    result = assess_application_impact(
        [
            {"identifier": "CVE-25", "impact": "low"},
            {"identifier": "CVE-25", "impact": "high"},
        ]
    )

    assert len(result.assessments) == 1
    assert result.assessments[0].impact == "HIGH"


def test_same_identifier_different_packages():
    result = assess_application_impact(
        [
            {
                "identifier": "CVE-26",
                "package": "alpha",
                "impact": "high",
            },
            {
                "identifier": "CVE-26",
                "package": "beta",
                "impact": "low",
            },
        ]
    )

    assert len(result.assessments) == 2


def test_deterministic_sorting():
    result = assess_application_impact(
        [
            {"identifier": "CVE-9"},
            {"identifier": "CVE-1"},
            {"identifier": "CVE-5"},
        ]
    )

    assert [x.identifier for x in result.assessments] == [
        "CVE-1",
        "CVE-5",
        "CVE-9",
    ]


def test_result_immutable():
    result = assess_application_impact(
        [{"identifier": "CVE-27"}]
    )

    with pytest.raises(FrozenInstanceError):
        result.assessed = False


def test_item_immutable():
    item = ApplicationImpactAssessment("CVE-28")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-29"


def test_result_type():
    result = assess_application_impact(
        [{"identifier": "CVE-30"}]
    )

    assert isinstance(
        result,
        ApplicationImpactAssessmentResult,
    )


def test_item_type():
    result = assess_application_impact(
        [{"identifier": "CVE-31"}]
    )

    assert isinstance(
        result.assessments[0],
        ApplicationImpactAssessment,
    )


def test_alias_function():
    data = [{"identifier": "CVE-32", "impact": "high"}]

    assert application_impact_assessment(data) == (
        assess_application_impact(data)
    )


def test_tuple_input():
    result = assess_application_impact(
        ({"identifier": "CVE-33"},)
    )

    assert result.assessed is True


def test_multiple_records():
    result = assess_application_impact(
        [
            {"identifier": "CVE-34", "impact": "critical"},
            {"identifier": "CVE-35", "impact": "high"},
            {"identifier": "CVE-36", "impact": "medium"},
            {"identifier": "CVE-37", "impact": "low"},
        ]
    )

    assert [x.impact for x in result.assessments] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]
