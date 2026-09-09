from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from sentinelshield.dependency_criticality_assessment import (
    DependencyCriticalityAssessment,
    DependencyCriticalityAssessmentResult,
    assess_dependency_criticality,
    dependency_criticality_assessment,
)


def test_none():
    result = assess_dependency_criticality(None)
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.assessed is False
    assert result.assessments == ()


@pytest.mark.parametrize(
    "value",
    ["package", b"package", 123, object()],
)
def test_unsupported_collection(value):
    result = assess_dependency_criticality(value)
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"
    assert result.assessed is False


def test_empty():
    result = assess_dependency_criticality([])
    assert result.status == "NO_DEPENDENCIES"
    assert result.assessed is False


def test_explicit_critical():
    result = assess_dependency_criticality(
        [{"name": "foo", "criticality": "critical"}]
    )

    assert result.status == "DEPENDENCY_CRITICALITY_ASSESSED"
    assert result.assessed is True
    assert result.assessments[0].criticality == "CRITICAL"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("CRIT", "CRITICAL"),
        ("CRITICAL", "CRITICAL"),
        ("VERY HIGH", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("MED", "MEDIUM"),
        ("MEDIUM", "MEDIUM"),
        ("MODERATE", "MEDIUM"),
        ("LOW", "LOW"),
        ("MINIMAL", "MINIMAL"),
        ("INFO", "MINIMAL"),
        ("INFORMATIONAL", "MINIMAL"),
        ("UNKNOWN", "UNKNOWN"),
    ],
)
def test_criticality_aliases(value, expected):
    result = assess_dependency_criticality(
        [{"name": "foo", "criticality": value}]
    )

    assert result.assessments[0].criticality == expected


def test_score_derives_criticality():
    result = assess_dependency_criticality(
        [{"name": "foo", "criticality_score": 85}]
    )

    assert result.assessments[0].criticality == "CRITICAL"
    assert result.assessments[0].score == 85.0


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
    result = assess_dependency_criticality(
        [{"name": "foo", "criticality_score": score}]
    )

    assert result.assessments[0].criticality == expected


@pytest.mark.parametrize("score", [-1, 100.1])
def test_invalid_score_range(score):
    result = assess_dependency_criticality(
        [{"name": "foo", "criticality_score": score}]
    )

    assert result.status == "INVALID_CRITICALITY_SCORE"


def test_boolean_criticality():
    result = assess_dependency_criticality(
        [{
            "name": "foo",
            "criticality": "high",
        }]
    )

    assert result.assessments[0].criticality == "HIGH"


def test_context_derivation_direct():
    result = assess_dependency_criticality(
        [{"name": "foo", "direct": True}]
    )

    assert result.assessments[0].criticality == "LOW"
    assert result.assessments[0].direct is True


def test_context_derivation_production():
    result = assess_dependency_criticality(
        [{"name": "foo", "production": True}]
    )

    assert result.assessments[0].criticality == "MEDIUM"
    assert result.assessments[0].production is True


def test_context_derivation_runtime():
    result = assess_dependency_criticality(
        [{"name": "foo", "runtime": True}]
    )

    assert result.assessments[0].criticality == "LOW"
    assert result.assessments[0].runtime is True


def test_context_derivation_internet():
    result = assess_dependency_criticality(
        [{"name": "foo", "internet_exposed": True}]
    )

    assert result.assessments[0].criticality == "LOW"
    assert result.assessments[0].internet_exposed is True


def test_context_combination():
    result = assess_dependency_criticality(
        [{
            "name": "foo",
            "direct": True,
            "production": True,
            "runtime": True,
            "internet_exposed": True,
        }]
    )

    assert result.assessments[0].criticality == "CRITICAL"


def test_explicit_criticality_has_priority_over_score():
    result = assess_dependency_criticality(
        [{
            "name": "foo",
            "criticality": "low",
            "criticality_score": 95,
        }]
    )

    assert result.assessments[0].criticality == "LOW"
    assert result.assessments[0].score == 95.0


def test_missing_criticality_is_unknown():
    result = assess_dependency_criticality(
        [{"name": "foo"}]
    )

    assert result.assessments[0].criticality == "UNKNOWN"


def test_invalid_dependency_name():
    result = assess_dependency_criticality(
        [{"name": "   "}]
    )

    assert result.status == "INVALID_DEPENDENCY_NAME"


@pytest.mark.parametrize(
    "value",
    [123, b"foo", None],
)
def test_invalid_dependency_name_values(value):
    data = {} if value is None else {"name": value}

    result = assess_dependency_criticality([data])

    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_name_normalization():
    result = assess_dependency_criticality(
        [{"name": " My_Package.Name "}]
    )

    assert result.assessments[0].dependency_name == "my-package-name"


def test_object_input():
    record = SimpleNamespace(
        dependency_name="Foo_Bar",
        production=True,
    )

    result = assess_dependency_criticality([record])

    assert result.assessments[0] == DependencyCriticalityAssessment(
        dependency_name="foo-bar",
        criticality="MEDIUM",
        score=None,
        direct=None,
        production=True,
        runtime=None,
        internet_exposed=None,
    )


def test_single_mapping():
    result = assess_dependency_criticality(
        {
            "name": "foo",
            "criticality": "high",
        }
    )

    assert result.assessed is True


def test_field_aliases():
    result = assess_dependency_criticality(
        [{
            "package_name": "Foo_Bar",
            "dependency_criticality": "high",
        }]
    )

    assert result.assessments[0].dependency_name == "foo-bar"
    assert result.assessments[0].criticality == "HIGH"


@pytest.mark.parametrize(
    "field",
    [
        "direct",
        "is_direct",
        "direct_dependency",
    ],
)
def test_direct_aliases(field):
    result = assess_dependency_criticality(
        [{"name": "foo", field: True}]
    )

    assert result.assessments[0].direct is True


def test_boolean_string_context():
    result = assess_dependency_criticality(
        [{
            "name": "foo",
            "direct": "yes",
            "production": "true",
            "runtime": "1",
            "internet_exposed": "exposed",
        }]
    )

    assert result.assessments[0].direct is True
    assert result.assessments[0].production is True
    assert result.assessments[0].runtime is True
    assert result.assessments[0].internet_exposed is True
    assert result.assessments[0].criticality == "CRITICAL"


def test_invalid_criticality_metadata():
    result = assess_dependency_criticality(
        [{"name": "foo", "criticality": "invalid"}]
    )

    assert result.status == "INVALID_CRITICALITY_METADATA"


def test_invalid_criticality_type():
    result = assess_dependency_criticality(
        [{"name": "foo", "criticality": 123}]
    )

    assert result.status == "INVALID_CRITICALITY_METADATA"


def test_invalid_direct_metadata():
    result = assess_dependency_criticality(
        [{"name": "foo", "direct": "maybe"}]
    )

    assert result.status == "INVALID_DIRECT_METADATA"


def test_invalid_production_metadata():
    result = assess_dependency_criticality(
        [{"name": "foo", "production": "maybe"}]
    )

    assert result.status == "INVALID_PRODUCTION_METADATA"


def test_invalid_runtime_metadata():
    result = assess_dependency_criticality(
        [{"name": "foo", "runtime": "maybe"}]
    )

    assert result.status == "INVALID_RUNTIME_METADATA"


def test_invalid_internet_metadata():
    result = assess_dependency_criticality(
        [{"name": "foo", "internet_exposed": "maybe"}]
    )

    assert result.status == "INVALID_INTERNET_EXPOSURE_METADATA"


def test_invalid_record():
    result = assess_dependency_criticality([None])
    assert result.status == "INVALID_DEPENDENCY_RECORD"


def test_duplicates_collapsed():
    result = assess_dependency_criticality(
        [
            {"name": "foo", "criticality": "low"},
            {"name": "foo", "criticality": "high"},
        ]
    )

    assert len(result.assessments) == 1
    assert result.assessments[0].criticality == "HIGH"


def test_deterministic_sorting():
    result = assess_dependency_criticality(
        [
            {"name": "zeta"},
            {"name": "alpha"},
            {"name": "middle"},
        ]
    )

    assert [x.dependency_name for x in result.assessments] == [
        "alpha",
        "middle",
        "zeta",
    ]


def test_result_immutable():
    result = assess_dependency_criticality(
        [{"name": "foo"}]
    )

    with pytest.raises(FrozenInstanceError):
        result.assessed = False


def test_item_immutable():
    item = DependencyCriticalityAssessment("foo")

    with pytest.raises(FrozenInstanceError):
        item.dependency_name = "bar"


def test_result_type():
    result = assess_dependency_criticality(
        [{"name": "foo"}]
    )

    assert isinstance(
        result,
        DependencyCriticalityAssessmentResult,
    )


def test_item_type():
    result = assess_dependency_criticality(
        [{"name": "foo"}]
    )

    assert isinstance(
        result.assessments[0],
        DependencyCriticalityAssessment,
    )


def test_alias_function():
    data = [{"name": "foo", "criticality": "high"}]

    assert dependency_criticality_assessment(data) == (
        assess_dependency_criticality(data)
    )


def test_tuple_input():
    result = assess_dependency_criticality(
        ({"name": "foo"},)
    )

    assert result.assessed is True


def test_multiple_dependencies():
    result = assess_dependency_criticality(
        [
            {"name": "alpha", "criticality": "critical"},
            {"name": "beta", "criticality": "high"},
            {"name": "gamma", "criticality": "medium"},
        ]
    )

    assert [x.criticality for x in result.assessments] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
    ]
