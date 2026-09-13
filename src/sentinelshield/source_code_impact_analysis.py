from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class SourceCodeImpact:
    path: str
    changed: bool
    affected_packages: tuple[str, ...]
    affected_modules: tuple[str, ...]
    impact_type: str


@dataclass(frozen=True)
class SourceCodeImpactAnalysisInput:
    changed_files: Mapping[str, Mapping[str, object]]
    dependency_changes: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class SourceCodeImpactAnalysisResult:
    impacts: tuple[SourceCodeImpact, ...]

    @property
    def affected(self) -> tuple[SourceCodeImpact, ...]:
        return tuple(
            impact
            for impact in self.impacts
            if impact.changed
        )

    @property
    def unaffected(self) -> tuple[SourceCodeImpact, ...]:
        return tuple(
            impact
            for impact in self.impacts
            if not impact.changed
        )


def _validate_input(
    request: SourceCodeImpactAnalysisInput,
) -> SourceCodeImpactAnalysisInput:
    if not isinstance(
        request,
        SourceCodeImpactAnalysisInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_SOURCE_CODE_IMPACT_ANALYSIS_INPUT"
        )

    if not isinstance(request.changed_files, Mapping):
        raise TypeError(
            "CHANGED_FILES_MUST_BE_MAPPING"
        )

    if not isinstance(request.dependency_changes, Mapping):
        raise TypeError(
            "DEPENDENCY_CHANGES_MUST_BE_MAPPING"
        )

    for path, metadata in request.changed_files.items():
        if not isinstance(path, str):
            raise TypeError(
                "CHANGED_FILE_PATH_MUST_BE_STRING"
            )

        if not path.strip():
            raise ValueError(
                "CHANGED_FILE_PATH_MUST_NOT_BE_EMPTY"
            )

        if not isinstance(metadata, Mapping):
            raise TypeError(
                "CHANGED_FILE_METADATA_MUST_BE_MAPPING"
            )

    for package, metadata in request.dependency_changes.items():
        if not isinstance(package, str):
            raise TypeError(
                "DEPENDENCY_NAME_MUST_BE_STRING"
            )

        if not package.strip():
            raise ValueError(
                "DEPENDENCY_NAME_MUST_NOT_BE_EMPTY"
            )

        if not isinstance(metadata, Mapping):
            raise TypeError(
                "DEPENDENCY_METADATA_MUST_BE_MAPPING"
            )

    return request


def _normalize_values(
    values: object,
) -> tuple[str, ...]:
    if values is None:
        return ()

    if isinstance(values, str):
        values = (values,)

    try:
        result = {
            value
            for value in values
            if isinstance(value, str) and value.strip()
        }
    except TypeError as exc:
        raise TypeError(
            "IMPACT_VALUES_MUST_BE_SEQUENCE"
        ) from exc

    return tuple(sorted(result))


def _package_matches_path(
    package: str,
    path: str,
) -> bool:
    normalized_package = package.replace("-", "_").lower()
    normalized_path = path.replace("\\", "/").lower()

    package_parts = normalized_package.split(".")

    return any(
        part and part in normalized_path
        for part in package_parts
    )


def _calculate_impact(
    path: str,
    file_metadata: Mapping[str, object],
    dependency_changes: Mapping[str, Mapping[str, object]],
) -> SourceCodeImpact:
    explicit_packages = _normalize_values(
        file_metadata.get("affected_packages")
    )

    explicit_modules = _normalize_values(
        file_metadata.get("affected_modules")
    )

    matched_packages = set(explicit_packages)

    for package in dependency_changes:
        if _package_matches_path(package, path):
            matched_packages.add(package)

    changed = bool(
        file_metadata.get("changed", True)
    )

    if not changed:
        impact_type = "unchanged"

    elif matched_packages or explicit_modules:
        impact_type = "affected"

    else:
        impact_type = "changed"

    return SourceCodeImpact(
        path=path,
        changed=changed,
        affected_packages=tuple(sorted(matched_packages)),
        affected_modules=explicit_modules,
        impact_type=impact_type,
    )


def analyze_source_code_impact(
    request: SourceCodeImpactAnalysisInput,
) -> SourceCodeImpactAnalysisResult:
    request = _validate_input(request)

    impacts = tuple(
        _calculate_impact(
            path,
            metadata,
            request.dependency_changes,
        )
        for path, metadata
        in sorted(request.changed_files.items())
    )

    return SourceCodeImpactAnalysisResult(
        impacts=impacts,
    )


def source_code_impact_analysis(
    request: SourceCodeImpactAnalysisInput,
) -> SourceCodeImpactAnalysisResult:
    return analyze_source_code_impact(request)
