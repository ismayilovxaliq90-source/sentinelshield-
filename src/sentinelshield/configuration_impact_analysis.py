from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ConfigurationImpact:
    setting: str
    package: str
    impact: str
    affected: bool
    reason: str


@dataclass(frozen=True)
class ConfigurationImpactAnalysisInput:
    configurations: Mapping[str, Mapping[str, object]]
    dependency_changes: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class ConfigurationImpactAnalysisResult:
    impacts: tuple[ConfigurationImpact, ...]

    @property
    def affected(self) -> tuple[ConfigurationImpact, ...]:
        return tuple(item for item in self.impacts if item.affected)

    @property
    def unaffected(self) -> tuple[ConfigurationImpact, ...]:
        return tuple(item for item in self.impacts if not item.affected)


def _validate_input(
    request: ConfigurationImpactAnalysisInput,
) -> ConfigurationImpactAnalysisInput:
    if not isinstance(request, ConfigurationImpactAnalysisInput):
        raise TypeError(
            "INPUT_MUST_BE_CONFIGURATION_IMPACT_ANALYSIS_INPUT"
        )

    if not isinstance(request.configurations, Mapping):
        raise TypeError("CONFIGURATIONS_MUST_BE_MAPPING")

    if not isinstance(request.dependency_changes, Mapping):
        raise TypeError("DEPENDENCY_CHANGES_MUST_BE_MAPPING")

    for setting, metadata in request.configurations.items():
        if not isinstance(setting, str):
            raise TypeError("CONFIGURATION_SETTING_MUST_BE_STRING")

        if not setting.strip():
            raise ValueError("CONFIGURATION_SETTING_MUST_NOT_BE_EMPTY")

        if not isinstance(metadata, Mapping):
            raise TypeError("CONFIGURATION_METADATA_MUST_BE_MAPPING")

        package = metadata.get("package")

        if not isinstance(package, str):
            raise TypeError("CONFIGURATION_PACKAGE_MUST_BE_STRING")

        if not package.strip():
            raise ValueError("CONFIGURATION_PACKAGE_MUST_NOT_BE_EMPTY")

    for package, metadata in request.dependency_changes.items():
        if not isinstance(package, str):
            raise TypeError("DEPENDENCY_NAME_MUST_BE_STRING")

        if not package.strip():
            raise ValueError("DEPENDENCY_NAME_MUST_NOT_BE_EMPTY")

        if not isinstance(metadata, Mapping):
            raise TypeError("DEPENDENCY_METADATA_MUST_BE_MAPPING")

    return request


def _normalize_values(value: object) -> tuple[str, ...]:
    if value is None:
        return ()

    if isinstance(value, str):
        value = (value,)

    try:
        values = tuple(value)
    except TypeError as exc:
        raise TypeError("CONFIGURATION_VALUES_MUST_BE_SEQUENCE") from exc

    result: list[str] = []

    for item in values:
        if not isinstance(item, str):
            raise TypeError("CONFIGURATION_VALUE_MUST_BE_STRING")

        item = item.strip()

        if item and item not in result:
            result.append(item)

    return tuple(sorted(result))


def _analyze_configuration(
    setting: str,
    metadata: Mapping[str, object],
    dependency_changes: Mapping[str, Mapping[str, object]],
) -> ConfigurationImpact:
    package = metadata["package"]
    change = dependency_changes.get(package)

    if change is None:
        return ConfigurationImpact(
            setting=setting,
            package=package,
            impact="NONE",
            affected=False,
            reason="NO_DEPENDENCY_CHANGE",
        )

    removed = set(_normalize_values(change.get("removed_configurations")))
    changed = set(_normalize_values(change.get("changed_configurations")))
    breaking = set(_normalize_values(change.get("breaking_configurations")))

    if setting in removed:
        return ConfigurationImpact(
            setting=setting,
            package=package,
            impact="BREAKING",
            affected=True,
            reason="CONFIGURATION_REMOVED",
        )

    if setting in breaking:
        return ConfigurationImpact(
            setting=setting,
            package=package,
            impact="BREAKING",
            affected=True,
            reason="CONFIGURATION_BREAKING_CHANGE",
        )

    if setting in changed:
        return ConfigurationImpact(
            setting=setting,
            package=package,
            impact="CHANGED",
            affected=True,
            reason="CONFIGURATION_CHANGED",
        )

    return ConfigurationImpact(
        setting=setting,
        package=package,
        impact="NONE",
        affected=False,
        reason="CONFIGURATION_UNAFFECTED",
    )


def analyze_configuration_impact(
    request: ConfigurationImpactAnalysisInput,
) -> ConfigurationImpactAnalysisResult:
    request = _validate_input(request)

    impacts = tuple(
        _analyze_configuration(
            setting,
            metadata,
            request.dependency_changes,
        )
        for setting, metadata in sorted(request.configurations.items())
    )

    return ConfigurationImpactAnalysisResult(impacts=impacts)



def configuration_impact_analysis(
    request: ConfigurationImpactAnalysisInput,
) -> ConfigurationImpactAnalysisResult:
    return analyze_configuration_impact(request)
