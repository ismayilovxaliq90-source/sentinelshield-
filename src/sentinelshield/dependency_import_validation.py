from dataclasses import dataclass
import importlib
from typing import Optional

__test__ = False


@dataclass(frozen=True)
class DependencyImportValidationInput:
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class DependencyImportValidationResult:
    valid: tuple[str, ...]
    invalid: tuple[str, ...]
    errors: tuple[tuple[str, str], ...]
    status: str


def validate_dependency_imports(
    request: DependencyImportValidationInput,
) -> DependencyImportValidationResult:
    if not isinstance(request, DependencyImportValidationInput):
        raise TypeError("INPUT_MUST_BE_DEPENDENCY_IMPORT_VALIDATION_INPUT")
    if not isinstance(request.dependencies, tuple):
        raise TypeError("DEPENDENCIES_MUST_BE_TUPLE")

    names = []
    for name in request.dependencies:
        if not isinstance(name, str):
            raise TypeError("DEPENDENCIES_MUST_CONTAIN_STRINGS")
        name = name.strip()
        if not name:
            raise ValueError("DEPENDENCY_NAME_MUST_NOT_BE_EMPTY")
        if "\x00" in name:
            raise ValueError("DEPENDENCY_NAME_CONTAINS_NULL_CHARACTER")
        names.append(name)

    valid, invalid, errors = [], [], []
    for name in sorted(set(names)):
        try:
            importlib.import_module(name)
            valid.append(name)
        except (ImportError, ModuleNotFoundError) as exc:
            invalid.append(name)
            errors.append((name, str(exc)))
        except Exception as exc:
            invalid.append(name)
            errors.append((name, f"{type(exc).__name__}: {exc}"))

    return DependencyImportValidationResult(
        valid=tuple(valid),
        invalid=tuple(invalid),
        errors=tuple(errors),
        status="PASS" if not invalid else "FAIL",
    )


def dependency_import_validation(
    request: DependencyImportValidationInput,
) -> DependencyImportValidationResult:
    return validate_dependency_imports(request)


__all__ = [
    "DependencyImportValidationInput",
    "DependencyImportValidationResult",
    "validate_dependency_imports",
    "dependency_import_validation",
]
