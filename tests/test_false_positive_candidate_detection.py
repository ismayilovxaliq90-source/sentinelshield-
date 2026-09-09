from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from sentinelshield.false_positive_candidate_detection import (
    FalsePositiveCandidate,
    FalsePositiveCandidateDetectionResult,
    detect_false_positive_candidates,
    false_positive_candidate_detection,
)


def test_none():
    result = detect_false_positive_candidates(None)

    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.detected is False
    assert result.candidates == ()


@pytest.mark.parametrize(
    "value",
    ["CVE-1", b"CVE-1", 123, object()],
)
def test_unsupported_collection(value):
    result = detect_false_positive_candidates(value)

    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"
    assert result.detected is False


def test_empty():
    result = detect_false_positive_candidates([])

    assert result.status == "NO_VULNERABILITIES"
    assert result.detected is False


def test_no_false_positive_signal():
    result = detect_false_positive_candidates(
        [{"identifier": "CVE-1"}]
    )

    item = result.candidates[0]

    assert result.status == "FALSE_POSITIVE_CANDIDATES_DETECTED"
    assert result.detected is True
    assert item.candidate is False
    assert item.reasons == ()
    assert item.confidence == "LOW"


def test_explicit_false_positive():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-2",
            "false_positive": True,
        }]
    )

    item = result.candidates[0]

    assert item.candidate is True
    assert item.reasons == ("EXPLICIT_FALSE_POSITIVE",)
    assert item.confidence == "LOW"


def test_explicit_false_positive_false():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-3",
            "false_positive": False,
        }]
    )

    assert result.candidates[0].candidate is False


def test_explicit_candidate():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-4",
            "false_positive_candidate": True,
        }]
    )

    assert result.candidates[0].candidate is True
    assert result.candidates[0].reasons == (
        "EXPLICIT_FALSE_POSITIVE_CANDIDATE",
    )


def test_not_affected():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-5",
            "affected": False,
        }]
    )

    assert result.candidates[0].candidate is True
    assert result.candidates[0].reasons == (
        "PACKAGE_NOT_AFFECTED",
    )


def test_not_reachable():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-6",
            "reachable": False,
        }]
    )

    assert result.candidates[0].candidate is True
    assert result.candidates[0].reasons == (
        "NOT_REACHABLE",
    )


def test_not_runtime_exposed():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-7",
            "runtime_exposed": False,
        }]
    )

    assert result.candidates[0].candidate is True
    assert result.candidates[0].reasons == (
        "NOT_RUNTIME_EXPOSED",
    )


def test_not_production_exposed():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-8",
            "production_exposed": False,
        }]
    )

    assert result.candidates[0].candidate is True
    assert result.candidates[0].reasons == (
        "NOT_PRODUCTION_EXPOSED",
    )


def test_not_internet_exposed():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-9",
            "internet_exposed": False,
        }]
    )

    assert result.candidates[0].candidate is True
    assert result.candidates[0].reasons == (
        "NOT_INTERNET_EXPOSED",
    )


def test_multiple_reasons():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-10",
            "affected": False,
            "reachable": False,
            "production_exposed": False,
        }]
    )

    item = result.candidates[0]

    assert item.candidate is True
    assert item.reasons == (
        "PACKAGE_NOT_AFFECTED",
        "NOT_REACHABLE",
        "NOT_PRODUCTION_EXPOSED",
    )
    assert item.confidence == "HIGH"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("true", True),
        ("yes", True),
        ("1", True),
        ("false", False),
        ("no", False),
        ("0", False),
    ],
)
def test_boolean_aliases(value, expected):
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-11",
            "false_positive": value,
        }]
    )

    assert result.candidates[0].candidate is expected


def test_identifier_required():
    result = detect_false_positive_candidates(
        [{"false_positive": True}]
    )

    assert result.status == "INVALID_VULNERABILITY_IDENTIFIER"


def test_identifier_normalization():
    result = detect_false_positive_candidates(
        [{"identifier": " cve-12 "}]
    )

    assert result.candidates[0].identifier == "CVE-12"


def test_package_normalization():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-13",
            "package_name": " My_Package.Name ",
        }]
    )

    assert result.candidates[0].package_name == "my-package-name"


def test_empty_package():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-14",
            "package_name": "   ",
        }]
    )

    assert result.candidates[0].package_name is None


def test_invalid_package():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-15",
            "package_name": 123,
        }]
    )

    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_invalid_false_positive_metadata():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-16",
            "false_positive": "maybe",
        }]
    )

    assert result.status == "INVALID_FALSE_POSITIVE_METADATA"


def test_invalid_candidate_metadata():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-17",
            "false_positive_candidate": "maybe",
        }]
    )

    assert result.status == (
        "INVALID_FALSE_POSITIVE_CANDIDATE_METADATA"
    )


def test_invalid_affected_metadata():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-18",
            "affected": "maybe",
        }]
    )

    assert result.status == "INVALID_AFFECTED_METADATA"


def test_invalid_reachability_metadata():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-19",
            "reachable": "maybe",
        }]
    )

    assert result.status == "INVALID_REACHABILITY_METADATA"


def test_invalid_runtime_metadata():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-20",
            "runtime_exposed": "maybe",
        }]
    )

    assert result.status == "INVALID_RUNTIME_EXPOSURE_METADATA"


def test_invalid_production_metadata():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-21",
            "production_exposed": "maybe",
        }]
    )

    assert result.status == (
        "INVALID_PRODUCTION_EXPOSURE_METADATA"
    )


def test_invalid_internet_metadata():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-22",
            "internet_exposed": "maybe",
        }]
    )

    assert result.status == (
        "INVALID_INTERNET_EXPOSURE_METADATA"
    )


def test_confidence_normalization():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-23",
            "affected": False,
            "confidence": "medium",
        }]
    )

    assert result.candidates[0].confidence == "MEDIUM"


def test_invalid_confidence():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-24",
            "confidence": "invalid",
        }]
    )

    assert result.status == "INVALID_CONFIDENCE_METADATA"


def test_object_record():
    record = SimpleNamespace(
        identifier="cve-25",
        package_name="Foo_Bar",
        reachable=False,
    )

    result = detect_false_positive_candidates([record])

    assert result.candidates[0] == FalsePositiveCandidate(
        identifier="CVE-25",
        package_name="foo-bar",
        candidate=True,
        reasons=("NOT_REACHABLE",),
        confidence="LOW",
    )


def test_single_mapping():
    result = detect_false_positive_candidates(
        {
            "identifier": "CVE-26",
            "reachable": False,
        }
    )

    assert result.detected is True


def test_field_aliases():
    result = detect_false_positive_candidates(
        [{
            "cve": "cve-27",
            "dependency_name": "foo_bar",
            "is_reachable": False,
        }]
    )

    assert result.candidates[0].identifier == "CVE-27"
    assert result.candidates[0].package_name == "foo-bar"
    assert result.candidates[0].candidate is True


def test_duplicate_records_combine_reasons():
    result = detect_false_positive_candidates(
        [
            {
                "identifier": "CVE-28",
                "affected": False,
            },
            {
                "identifier": "CVE-28",
                "reachable": False,
            },
        ]
    )

    assert len(result.candidates) == 1
    assert result.candidates[0].reasons == (
        "PACKAGE_NOT_AFFECTED",
        "NOT_REACHABLE",
    )
    assert result.candidates[0].confidence == "MEDIUM"


def test_same_identifier_different_packages():
    result = detect_false_positive_candidates(
        [
            {
                "identifier": "CVE-29",
                "package": "alpha",
                "reachable": False,
            },
            {
                "identifier": "CVE-29",
                "package": "beta",
                "reachable": False,
            },
        ]
    )

    assert len(result.candidates) == 2


def test_deterministic_sorting():
    result = detect_false_positive_candidates(
        [
            {"identifier": "CVE-9"},
            {"identifier": "CVE-1"},
            {"identifier": "CVE-5"},
        ]
    )

    assert [x.identifier for x in result.candidates] == [
        "CVE-1",
        "CVE-5",
        "CVE-9",
    ]


def test_unknown_does_not_create_candidate():
    result = detect_false_positive_candidates(
        [{
            "identifier": "CVE-30",
            "reachable": None,
            "runtime_exposed": None,
            "production_exposed": None,
            "internet_exposed": None,
        }]
    )

    assert result.candidates[0].candidate is False


def test_result_immutable():
    result = detect_false_positive_candidates(
        [{"identifier": "CVE-31"}]
    )

    with pytest.raises(FrozenInstanceError):
        result.detected = False


def test_item_immutable():
    item = FalsePositiveCandidate("CVE-32")

    with pytest.raises(FrozenInstanceError):
        item.identifier = "CVE-33"


def test_result_type():
    result = detect_false_positive_candidates(
        [{"identifier": "CVE-34"}]
    )

    assert isinstance(
        result,
        FalsePositiveCandidateDetectionResult,
    )


def test_item_type():
    result = detect_false_positive_candidates(
        [{"identifier": "CVE-35"}]
    )

    assert isinstance(
        result.candidates[0],
        FalsePositiveCandidate,
    )


def test_alias_function():
    data = [{
        "identifier": "CVE-36",
        "reachable": False,
    }]

    assert false_positive_candidate_detection(data) == (
        detect_false_positive_candidates(data)
    )


def test_tuple_input():
    result = detect_false_positive_candidates(
        ({"identifier": "CVE-37"},)
    )

    assert result.detected is True


def test_multiple_records():
    result = detect_false_positive_candidates(
        [
            {
                "identifier": "CVE-38",
                "affected": False,
            },
            {
                "identifier": "CVE-39",
                "reachable": False,
            },
            {
                "identifier": "CVE-40",
            },
        ]
    )

    assert [x.candidate for x in result.candidates] == [
        True,
        True,
        False,
    ]
