from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ImportCompatibility:
    module: str
    package: str
    compatible: bool
    reason: str


@dataclass(frozen=True)
class ImportCompatibilityAnalysisInput:
    imports: Mapping[str, Mapping[str, object]]
    dependency_changes: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class ImportCompatibilityAnalysisResult:
    results: tuple[ImportCompatibility, ...]

    @property
    def compatible(self) -> tuple[ImportCompatibility, ...]:
        return tuple(
            item for item in self.results
            if item.compatible
        )

    @property
    def incompatible(self) -> tuple[ImportCompatibility, ...]:
        return tuple(
            item for item in self.results
            if not item.compatible
        )


def _validate_input(
    request: ImportCompatibilityAnalysisInput,
) -> ImportCompatibilityAnalysisInput:
    if not isinstance(
        request,
        ImportCompatibilityAnalysisInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_IMPORT_COMPATIBILITY_ANALYSIS_INPUT"
        )

    if not isinstance(request.imports, Mapping):
        raise TypeError("IMPORTS_MUST_BE_MAPPING")

    if not isinstance(request.dependency_changes, Mapping):
        raise TypeError(
            "DEPENDENCY_CHANGES_MUST_BE_MAPPING"
        )

    for module, metadata in request.imports.items():
        if not isinstance(module, str):
            raise TypeError(
                "IMPORT_MODULE_MUST_BE_STRING"
            )

        if not module.strip():
            raise ValueError(
                "IMPORT_MODULE_MUST_NOT_BE_EMPTY"
            )

        if not isinstance(metadata, Mapping):
            raise TypeError(
                "IMPORT_METADATA_MUST_BE_MAPPING"
            )

        package = metadata.get("package")

        if not isinstance(package, str):
            raise TypeError(
                "IMPORT_PACKAGE_MUST_BE_STRING"
            )

        if not package.strip():
            raise ValueError(
                "IMPORT_PACKAGE_MUST_NOT_BE_EMPTY"
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


def _normalize_modules(value: object) -> tuple[str, ...]:
    if value is None:
        return ()

    if isinstance(value, str):
        return (value,)

    try:
        values = value
        return tuple(
            sorted(
                {
                    item
                    for item in values
                    if isinstance(item, str) and item.strip()
                }
            )
        )
    except TypeError as exc:
        raise TypeError(
            "MODULES_MUST_BE_SEQUENCE"
        ) from exc


def _analyze_import(
    module: str,
    metadata: Mapping[str, object],
    dependency_changes: Mapping[str, Mapping[str, object]],
) -> ImportCompatibility:
    package = metadata["package"]

    change = dependency_changes.get(package)

    if change is None:
        return ImportCompatibility(
            module=module,
            package=package,
            compatible=True,
            reason="NO_DEPENDENCY_CHANGE",
        )

    removed_modules = set(
        _normalize_modules(
            change.get("removed_modules")
        )
    )

    incompatible_modules = set(
        _normalize_modules(
            change.get("incompatible_modules")
        )
    )

    if module in removed_modules:
        return ImportCompatibility(
            module=module,
            package=package,
            compatible=False,
            reason="IMPORTED_MODULE_REMOVED",
        )

    if module in incompatible_modules:
        return ImportCompatibility(
            module=module,
            package=package,
            compatible=False,
            reason="IMPORTED_MODULE_INCOMPATIBLE",
        )

    return ImportCompatibility(
        module=module,
        package=package,
        compatible=True,
        reason="IMPORT_REMAINS_COMPATIBLE",
    )


def analyze_import_compatibility(
    request: ImportCompatibilityAnalysisInput,
) -> ImportCompatibilityAnalysisResult:
    request = _validate_input(request)

    results = tuple(
        _analyze_import(
            module,
            metadata,
            request.dependency_changes,
        )
        for module, metadata
        in sorted(request.imports.items())
    )

    return ImportCompatibilityAnalysisResult(
        results=results,
    )


def import_compatibility_analysis(
    request: ImportCompatibilityAnalysisInput,
) -> ImportCompatibilityAnalysisResult:
    return analyze_import_compatibility(request)


