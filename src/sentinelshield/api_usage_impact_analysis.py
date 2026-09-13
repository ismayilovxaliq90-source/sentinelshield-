from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class APIUsageImpact:
    module: str
    package: str
    impact: str
    affected: bool
    reason: str


@dataclass(frozen=True)
class APIUsageImpactAnalysisInput:
    api_usages: Mapping[str, Mapping[str, object]]
    dependency_changes: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class APIUsageImpactAnalysisResult:
    impacts: tuple[APIUsageImpact, ...]

    @property
    def affected(self) -> tuple[APIUsageImpact, ...]:
        return tuple(
            item for item in self.impacts
            if item.affected
        )

    @property
    def unaffected(self) -> tuple[APIUsageImpact, ...]:
        return tuple(
            item for item in self.impacts
            if not item.affected
        )


def _validate_input(
    request: APIUsageImpactAnalysisInput,
) -> APIUsageImpactAnalysisInput:
    if not isinstance(
        request,
        APIUsageImpactAnalysisInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_API_USAGE_IMPACT_ANALYSIS_INPUT"
        )

    if not isinstance(request.api_usages, Mapping):
        raise TypeError("API_USAGES_MUST_BE_MAPPING")

    if not isinstance(request.dependency_changes, Mapping):
        raise TypeError(
            "DEPENDENCY_CHANGES_MUST_BE_MAPPING"
        )

    for usage, metadata in request.api_usages.items():
        if not isinstance(usage, str):
            raise TypeError("API_USAGE_MUST_BE_STRING")

        if not usage.strip():
            raise ValueError("API_USAGE_MUST_NOT_BE_EMPTY")

        if not isinstance(metadata, Mapping):
            raise TypeError("API_USAGE_METADATA_MUST_BE_MAPPING")

        package = metadata.get("package")

        if not isinstance(package, str):
            raise TypeError("API_USAGE_PACKAGE_MUST_BE_STRING")

        if not package.strip():
            raise ValueError(
                "API_USAGE_PACKAGE_MUST_NOT_BE_EMPTY"
            )

    for package, metadata in request.dependency_changes.items():
        if not isinstance(package, str):
            raise TypeError("DEPENDENCY_NAME_MUST_BE_STRING")

        if not package.strip():
            raise ValueError(
                "DEPENDENCY_NAME_MUST_NOT_BE_EMPTY"
            )

        if not isinstance(metadata, Mapping):
            raise TypeError(
                "DEPENDENCY_METADATA_MUST_BE_MAPPING"
            )

    return request


def _normalize_values(value: object) -> tuple[str, ...]:
    if value is None:
        return ()

    if isinstance(value, str):
        value = (value,)

    try:
        values = tuple(value)
    except TypeError as exc:
        raise TypeError(
            "API_VALUES_MUST_BE_SEQUENCE"
        ) from exc

    result: list[str] = []

    for item in values:
        if not isinstance(item, str):
            raise TypeError(
                "API_VALUE_MUST_BE_STRING"
            )

        item = item.strip()

        if item and item not in result:
            result.append(item)

    return tuple(sorted(result))


def _analyze_usage(
    usage: str,
    metadata: Mapping[str, object],
    dependency_changes: Mapping[str, Mapping[str, object]],
) -> APIUsageImpact:
    package = metadata["package"]
    change = dependency_changes.get(package)

    if change is None:
        return APIUsageImpact(
            module=usage,
            package=package,
            impact="NONE",
            affected=False,
            reason="NO_DEPENDENCY_CHANGE",
        )

    removed_apis = set(
        _normalize_values(change.get("removed_apis"))
    )

    changed_apis = set(
        _normalize_values(change.get("changed_apis"))
    )

    breaking_apis = set(
        _normalize_values(change.get("breaking_apis"))
    )

    if usage in removed_apis:
        return APIUsageImpact(
            module=usage,
            package=package,
            impact="BREAKING",
            affected=True,
            reason="API_REMOVED",
        )

    if usage in breaking_apis:
        return APIUsageImpact(
            module=usage,
            package=package,
            impact="BREAKING",
            affected=True,
            reason="API_BREAKING_CHANGE",
        )

    if usage in changed_apis:
        return APIUsageImpact(
            module=usage,
            package=package,
            impact="CHANGED",
            affected=True,
            reason="API_CHANGED",
        )

    return APIUsageImpact(
        module=usage,
        package=package,
        impact="NONE",
        affected=False,
        reason="API_USAGE_UNAFFECTED",
    )


def analyze_api_usage_impact(
    request: APIUsageImpactAnalysisInput,
) -> APIUsageImpactAnalysisResult:
    request = _validate_input(request)

    impacts = tuple(
        _analyze_usage(
            usage,
            metadata,
            request.dependency_changes,
        )
        for usage, metadata in sorted(
            request.api_usages.items()
        )
    )

    return APIUsageImpactAnalysisResult(
        impacts=impacts,
    )


def api_usage_impact_analysis(
    request: APIUsageImpactAnalysisInput,
) -> APIUsageImpactAnalysisResult:
    return analyze_api_usage_impact(request)
