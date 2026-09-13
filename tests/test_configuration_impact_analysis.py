import pytest

from sentinelshield.configuration_impact_analysis import (
    ConfigurationImpactAnalysisInput,
    ConfigurationImpactAnalysisResult,
    analyze_configuration_impact,
    configuration_impact_analysis,
)


def test_no_dependency_change():
    request = ConfigurationImpactAnalysisInput(
        configurations={"SETTING_A": {"package": "pkg-a"}},
        dependency_changes={},
    )

    result = analyze_configuration_impact(request)

    assert result.impacts[0].impact == "NONE"
    assert result.impacts[0].affected is False
    assert result.impacts[0].reason == "NO_DEPENDENCY_CHANGE"


def test_removed_configuration():
    request = ConfigurationImpactAnalysisInput(
        configurations={"SETTING_A": {"package": "pkg-a"}},
        dependency_changes={
            "pkg-a": {"removed_configurations": ["SETTING_A"]}
        },
    )

    result = analyze_configuration_impact(request)

    assert result.impacts[0].impact == "BREAKING"
    assert result.impacts[0].affected is True
    assert result.impacts[0].reason == "CONFIGURATION_REMOVED"


def test_breaking_configuration():
    request = ConfigurationImpactAnalysisInput(
        configurations={"SETTING_B": {"package": "pkg-b"}},
        dependency_changes={
            "pkg-b": {"breaking_configurations": ["SETTING_B"]}
        },
    )

    result = analyze_configuration_impact(request)

    assert result.impacts[0].impact == "BREAKING"
    assert result.impacts[0].affected is True
    assert result.impacts[0].reason == "CONFIGURATION_BREAKING_CHANGE"


def test_changed_configuration():
    request = ConfigurationImpactAnalysisInput(
        configurations={"SETTING_C": {"package": "pkg-c"}},
        dependency_changes={
            "pkg-c": {"changed_configurations": ["SETTING_C"]}
        },
    )

    result = analyze_configuration_impact(request)

    assert result.impacts[0].impact == "CHANGED"
    assert result.impacts[0].affected is True
    assert result.impacts[0].reason == "CONFIGURATION_CHANGED"


def test_unaffected_configuration():
    request = ConfigurationImpactAnalysisInput(
        configurations={
            "SETTING_A": {"package": "pkg-a"},
        },
        dependency_changes={
            "pkg-a": {"changed_configurations": ["OTHER_SETTING"]},
        },
    )

    result = analyze_configuration_impact(request)

    assert len(result.affected) == 0
    assert len(result.unaffected) == 1
    assert result.unaffected[0].reason == "CONFIGURATION_UNAFFECTED"


def test_removed_has_priority_over_breaking_and_changed():
    request = ConfigurationImpactAnalysisInput(
        configurations={"SETTING_A": {"package": "pkg-a"}},
        dependency_changes={
            "pkg-a": {
                "removed_configurations": ["SETTING_A"],
                "breaking_configurations": ["SETTING_A"],
                "changed_configurations": ["SETTING_A"],
            }
        },
    )

    result = analyze_configuration_impact(request)

    assert result.impacts[0].reason == "CONFIGURATION_REMOVED"
    assert result.impacts[0].impact == "BREAKING"
