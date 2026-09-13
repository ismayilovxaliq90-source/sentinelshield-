from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class DependencyCompatibilityImpact:
    dependency: str
    package: str
    impact: str
    affected: bool
    reason: str


@dataclass(frozen=True)
class DependencyCompatibilityAnalysisInput:
    dependencies: Mapping[str, Mapping[str, object]]
    dependency_changes: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class DependencyCompatibilityAnalysisResult:
    impacts: tuple[DependencyCompatibilityImpact, ...]

    @property
    def affected(self) -> tuple[DependencyCompatibilityImpact, ...]:
        return tuple(
            item for item in self.impacts
            if item.affected
        )

    @property
    def unaffected(self) -> tuple[DependencyCompatibilityImpact, ...]:
        return tuple(
            item for item in self.impacts
            if not item.affected
        )

def _validate_input(
    request: DependencyCompatibilityAnalysisInput,
) -> DependencyCompatibilityAnalysisInput:
    if not isinstance(
        request,
        DependencyCompatibilityAnalysisInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_DEPENDENCY_COMPATIBILITY_ANALYSIS_INPUT"
        )

    if not isinstance(request.dependencies, Mapping):
        raise TypeError("DEPENDENCIES_MUST_BE_MAPPING")

    if not isinstance(request.dependency_changes, Mapping):
        raise TypeError("DEPENDENCY_CHANGES_MUST_BE_MAPPING")

    return request


def _analyze_dependency(
    dependency: str,
    metadata: Mapping[str, object],
    dependency_changes: Mapping[str, Mapping[str, object]],
) -> DependencyCompatibilityImpact:
    package = metadata["package"]
    change = dependency_changes.get(package)

    if change is None:
        return DependencyCompatibilityImpact(
            dependency=dependency,
            package=package,
            impact="NONE",
            affected=False,
            reason="NO_DEPENDENCY_CHANGE",
        )

    incompatible = change.get(
        "incompatible_dependencies",
        (),
    )
    changed = change.get(
        "changed_dependencies",
        (),
    )

    if dependency in incompatible:
        return DependencyCompatibilityImpact(
            dependency=dependency,
            package=package,
            impact="BREAKING",
            affected=True,
            reason="DEPENDENCY_INCOMPATIBLE",
        )

    if dependency in changed:
        return DependencyCompatibilityImpact(
            dependency=dependency,
            package=package,
            impact="CHANGED",
            affected=True,
            reason="DEPENDENCY_COMPATIBILITY_CHANGED",
        )

    return DependencyCompatibilityImpact(
        dependency=dependency,
        package=package,
        impact="NONE",
        affected=False,
        reason="DEPENDENCY_COMPATIBILITY_UNAFFECTED",
    )

def analyze_dependency_compatibility(
    request: DependencyCompatibilityAnalysisInput,
) -> DependencyCompatibilityAnalysisResult:
    request = _validate_input(request)

    impacts = tuple(
        _analyze_dependency(
            dependency,
            metadata,
            request.dependency_changes,
        )
        for dependency, metadata
        in sorted(request.dependencies.items())
    )

    return DependencyCompatibilityAnalysisResult(
        impacts=impacts,
    )


def dependency_compatibility_analysis(
    request: DependencyCompatibilityAnalysisInput,
) -> DependencyCompatibilityAnalysisResult:
    return analyze_dependency_compatibility(request)
