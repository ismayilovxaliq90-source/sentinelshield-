from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from sentinelshield.reachability_assessment import (
    ReachabilityAssessment,
    ReachabilityAssessmentResult,
    assess_reachability,
    reachability_assessment,
)


def test_none():
    result = assess_reachability(None)
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.assessed is False
    assert result.assessments == ()


@pytest.mark.parametrize("value", ["CVE-1", b"CVE-1", 123, object()])
def test_unsupported_collection(value):
    result = assess_reachability(value)
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"
    assert result.assessed is False


def test_empty():
    result = assess_reachability([])
    assert result.status == "NO_VULNERABILITIES"
    assert result.assessed is False


def test_reachable_true():
    result = assess_reachability(
        [{"identifier": "CVE-1", "reachable": True}]
    )
    assert result.status == "REACHABILITY_ASSESSED"
    assert result.assessed is True
    assert result.assessments[0].reachable is True
    assert result.assessments[0].status == "REACHABLE"


def test_reachable_false():
    result = assess_reachability(
        [{"identifier": "CVE-2", "reachable": False}]
    )
    assert result.assessments[0].reachable is False
    assert result.assessments[0].status == "NOT_REACHABLE"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("true", True),
        ("yes", True),
        ("1", True),
        ("reachable", True),
        ("false", False),
        ("no", False),
        ("0", False),
        ("unreachable", False),
    ],
)
def test_reachability_aliases(value, expected):
    result = assess_reachability(
        [{"identifier": "CVE-3", "reachability": value}]
    )
    assert result.assessments[0].reachable is expected


def test_integer_boolean_values():
    true_result = assess_reachability(
        [{"identifier": "CVE-4", "reachable": 1}]
    )
    false_result = assess_reachability(
        [{"identifier": "CVE-5", "reachable": 0}]
    )

    assert true_result.assessments[0].reachable is True
    assert false_result.assessments[0].reachable is False


def test_missing_metadata_is_unknown():
    result = assess_reachability(
        [{"identifier": "CVE-6"}]
    )

    item = result.assessments[0]

    assert item.reachable is None
    assert item.status == "UNKNOWN"


def test_invalid_reachability():
    result = assess_reachability(
        [{"identifier": "CVE-7", "reachable": "maybe"}]
    )
    assert result.status == "INVALID_REACHABILITY_METADATA"
    assert result.assessed is False


@pytest.mark.parametrize(
    "value",
    [2, -1, object(), b"true"],
)
def test_invalid_reachability_types(value):
    result = assess_reachability(
        [{"identifier": "CVE-8", "reachable": value}]
    )
    assert result.status == "INVALID_REACHABILITY_METADATA"


def test_identifier_required():
    result = assess_reachability(
        [{"reachable": True}]
    )
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_empty_identifier():
    result = assess_reachability(
        [{"identifier": "   ", "reachable": True}]
    )
    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_identifier_normalization():
    result = assess_reachability(
        [{"identifier": " cve-9 ", "reachable": True}]
    )
    assert result.assessments[0].identifier == "CVE-9"


def test_package_normalization():
    result = assess_reachability(
        [{
            "identifier": "CVE-10",
            "package_name": " My_Package.Name ",
            "reachable": True,
        }]
    )
    assert result.assessments[0].package_name == "my-package-name"


def test_empty_package_becomes_none():
    result = assess_reachability(
        [{
            "identifier": "CVE-11",
            "package_name": "   ",
            "reachable": True,
        }]
    )
    assert result.assessments[0].package_name is None


def test_invalid_package():
    result = assess_reachability(
        [{
            "identifier": "CVE-12",
            "package_name": 123,
            "reachable": True,
        }]
    )
    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_object_record():
    record = SimpleNamespace(
        identifier="cve-13",
        package_name="foo_bar",
        reachable=True,
    )

    result = assess_reachability([record])

    assert result.assessments == (
        ReachabilityAssessment(
            "CVE-13",
            "foo-bar",
            True,
            "REACHABLE",
        ),
    )


def test_single_mapping():
    result = assess_reachability(
        {
            "identifier": "CVE-14",
            "reachable": True,
        }
    )
    assert result.assessed is True


def test_field_aliases():
    result = assess_reachability(
        [{
            "cve": "cve-15",
            "dependency_name": "foo_bar",
            "is_reachable": True,
        }]
    )

    assert result.assessments == (
        ReachabilityAssessment(
            "CVE-15",
            "foo-bar",
            True,
            "REACHABLE",
        ),
    )


def test_duplicate_records_deduplicated():
    result = assess_reachability(
        [
            {"identifier": "CVE-16", "reachable": True},
            {"identifier": "CVE-16", "reachable": True},
            {"identifier": "CVE-16", "reachable": True},
        ]
    )

    assert len(result.assessments) == 1


def test_same_identifier_different_packages_preserved():
    result = assess_reachability(
        [
            {
                "identifier": "CVE-17",
                "package": "alpha",
                "reachable": True,
            },
            {
                "identifier": "CVE-17",
                "package": "beta",
                "reachable": False,
            },
        ]
    )

    assert len(result.assessments) == 2


def test_deterministic_sorting():
    result = assess_reachability(
        [
            {"identifier": "CVE-9", "reachable": True},
            {"identifier": "CVE-1", "reachable": True},
            {"identifier": "CVE-5", "reachable": True},
        ]
    )

    assert [item.identifier for item in result.assessments] == [
        "CVE-1",
        "CVE-5",
        "CVE-9",
    ]


def test_reachable_from_root_alias():
    result = assess_reachability(
        [{
            "identifier": "CVE-18",
            "reachable_from_root": True,
        }]
    )

    assert result.assessments[0].status == "REACHABLE"


def test_dependency_reachable_alias():
    result = assess_reachability(
        [{
            "identifier": "CVE-19",
            "dependency_reachable": False,
        }]
    )

    assert result.assessments[0].status == "NOT_REACHABLE"


def test_field_priority():
    result = assess_reachability(
        [{
            "identifier": "CVE-20",
            "reachable": True,
            "is_reachable": False,
        }]
    )

    assert result.assessments[0].reachable is True


def test_result_immutable():
    result = assess_reachability(
        [{"identifier": "CVE-21", "reachable": True}]
    )

    with pytest.raises(FrozenInstanceError):
        result.assessed = False


def test_item_immutable():
    item = ReachabilityAssessment("CVE-22")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-23"


def test_result_type():
    result = assess_reachability(
        [{"identifier": "CVE-24", "reachable": True}]
    )

    assert isinstance(result, ReachabilityAssessmentResult)


def test_item_type():
    result = assess_reachability(
        [{"identifier": "CVE-25", "reachable": True}]
    )

    assert isinstance(result.assessments[0], ReachabilityAssessment)


def test_alias_function():
    data = [{"identifier": "CVE-26", "reachable": True}]

    assert reachability_assessment(data) == assess_reachability(data)


def test_tuple_input():
    result = assess_reachability(
        ({"identifier": "CVE-27", "reachable": True},)
    )

    assert result.assessed is True


def test_multiple_metadata_fields():
    result = assess_reachability(
        [{
            "identifier": "CVE-28",
            "reachable": True,
            "is_reachable": True,
            "reachability": "reachable",
        }]
    )

    assert result.assessments[0].reachable is True
    assert result.assessments[0].status == "REACHABLE"
