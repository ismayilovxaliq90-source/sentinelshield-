import pytest

from sentinelshield.api_usage_impact_analysis import (
    APIUsageImpact,
    APIUsageImpactAnalysisInput,
    analyze_api_usage_impact,
    api_usage_impact_analysis,
)


def test_no_dependency_change():
    result = analyze_api_usage_impact(
        APIUsageImpactAnalysisInput(
            api_usages={"client.get": {"package": "requests"}},
            dependency_changes={},
        )
    )

    assert result.impacts == (
        APIUsageImpact(
            module="client.get",
            package="requests",
            impact="NONE",
            affected=False,
            reason="NO_DEPENDENCY_CHANGE",
        ),
    )


def test_removed_api_is_breaking():
    result = analyze_api_usage_impact(
        APIUsageImpactAnalysisInput(
            api_usages={"client.get": {"package": "requests"}},
            dependency_changes={
                "requests": {"removed_apis": ["client.get"]},
            },
        )
    )

    assert result.affected[0].impact == "BREAKING"
    assert result.affected[0].reason == "API_REMOVED"


def test_breaking_api_is_breaking():
    result = analyze_api_usage_impact(
        APIUsageImpactAnalysisInput(
            api_usages={"client.post": {"package": "requests"}},
            dependency_changes={
                "requests": {"breaking_apis": ["client.post"]},
            },
        )
    )

    assert result.affected[0].impact == "BREAKING"
    assert result.affected[0].reason == "API_BREAKING_CHANGE"

def test_changed_api_is_changed():
    result = analyze_api_usage_impact(
        APIUsageImpactAnalysisInput(
            api_usages={"client.get": {"package": "requests"}},
            dependency_changes={
                "requests": {"changed_apis": ["client.get"]},
            },
        )
    )

    assert result.affected[0].impact == "CHANGED"
    assert result.affected[0].reason == "API_CHANGED"


def test_unaffected_api():
    result = analyze_api_usage_impact(
        APIUsageImpactAnalysisInput(
            api_usages={"client.delete": {"package": "requests"}},
            dependency_changes={
                "requests": {"changed_apis": ["client.get"]},
            },
        )
    )

    assert result.unaffected[0].impact == "NONE"
    assert result.unaffected[0].reason == "API_USAGE_UNAFFECTED"


def test_affected_and_unaffected_partition():
    result = analyze_api_usage_impact(
        APIUsageImpactAnalysisInput(
            api_usages={
                "client.get": {"package": "requests"},
                "client.post": {"package": "requests"},
            },
            dependency_changes={
                "requests": {"changed_apis": ["client.get"]},
            },
        )
    )

    assert len(result.affected) == 1
    assert len(result.unaffected) == 1

def test_affected_and_unaffected_partition():
    result = analyze_api_usage_impact(
        APIUsageImpactAnalysisInput(
            api_usages={
                "client.get": {"package": "requests"},
                "client.post": {"package": "requests"},
            },
            dependency_changes={
                "requests": {"changed_apis": ["client.get"]},
            },
        )
    )

    assert len(result.affected) == 1
    assert len(result.unaffected) == 1

def test_invalid_request_type():
    with pytest.raises(TypeError, match="INPUT_MUST_BE_API_USAGE_IMPACT_ANALYSIS_INPUT"):
        analyze_api_usage_impact(None)


def test_api_usages_must_be_mapping():
    with pytest.raises(TypeError, match="API_USAGES_MUST_BE_MAPPING"):
        analyze_api_usage_impact(
            APIUsageImpactAnalysisInput(
                api_usages=[],
                dependency_changes={},
            )
        )


def test_api_usage_key_must_be_string():
    with pytest.raises(TypeError, match="API_USAGE_MUST_BE_STRING"):
        analyze_api_usage_impact(
            APIUsageImpactAnalysisInput(
                api_usages={1: {"package": "pkg"}},
                dependency_changes={},
            )
        )


def test_api_usage_metadata_must_be_mapping():
    with pytest.raises(TypeError, match="API_USAGE_METADATA_MUST_BE_MAPPING"):
        analyze_api_usage_impact(
            APIUsageImpactAnalysisInput(
                api_usages={"api": []},
                dependency_changes={},
            )
        )


def test_api_usage_package_must_be_string():
    with pytest.raises(TypeError, match="API_USAGE_PACKAGE_MUST_BE_STRING"):
        analyze_api_usage_impact(
            APIUsageImpactAnalysisInput(
                api_usages={"api": {"package": 123}},
                dependency_changes={},
            )
        )

def test_dependency_name_must_be_string():
    with pytest.raises(TypeError, match="DEPENDENCY_NAME_MUST_BE_STRING"):
        analyze_api_usage_impact(
            APIUsageImpactAnalysisInput(
                api_usages={},
                dependency_changes={1: {}},
            )
        )


def test_dependency_metadata_must_be_mapping():
    with pytest.raises(TypeError, match="DEPENDENCY_METADATA_MUST_BE_MAPPING"):
        analyze_api_usage_impact(
            APIUsageImpactAnalysisInput(
                api_usages={},
                dependency_changes={"pkg": []},
            )
        )


def test_alias_matches_main_function():
    request = APIUsageImpactAnalysisInput(
        api_usages={"client.get": {"package": "requests"}},
        dependency_changes={
            "requests": {"changed_apis": ["client.get"]},
        },
    )

    assert api_usage_impact_analysis(request) == analyze_api_usage_impact(
        request
    )

    assert api_usage_impact_analysis(request) == analyze_api_usage_impact(
        request
    )
