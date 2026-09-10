from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


class DependencyVersionVerificationError(ValueError):
    """Raised when dependency version verification input is invalid."""


_VERSION_PATTERN = re.compile(
    r"^[0-9]+(?:\.[0-9]+){0,3}"
    r"(?:[-+][0-9A-Za-z.-]+)?$"
)


def normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise DependencyVersionVerificationError(
            "Dependency name must be a string"
        )

    value = name.strip().lower()

    if not value:
        raise DependencyVersionVerificationError(
            "Dependency name cannot be empty"
        )

    if "\x00" in value or any(ord(ch) < 32 for ch in value):
        raise DependencyVersionVerificationError(
            "Dependency name contains control characters"
        )

    return value.replace("_", "-").replace(".", "-")


def is_valid_version(version: str) -> bool:
    if not isinstance(version, str):
        return False

    value = version.strip()

    if not value:
        return False

    return bool(_VERSION_PATTERN.fullmatch(value))


@dataclass(frozen=True)
class ResolvedDependencyVersion:
    name: str
    version: str

    def __post_init__(self) -> None:
        normalize_name(self.name)

        if not is_valid_version(self.version):
            raise DependencyVersionVerificationError(
                f"Invalid resolved version for {self.name}: {self.version!r}"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "name": normalize_name(self.name),
            "version": self.version.strip(),
        }


@dataclass(frozen=True)
class ExpectedDependencyVersion:
    name: str
    version: str

    def __post_init__(self) -> None:
        normalize_name(self.name)

        if not is_valid_version(self.version):
            raise DependencyVersionVerificationError(
                f"Invalid expected version for {self.name}: {self.version!r}"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "name": normalize_name(self.name),
            "version": self.version.strip(),
        }


@dataclass(frozen=True)
class DependencyVersionMismatch:
    name: str
    expected_version: str
    actual_version: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": normalize_name(self.name),
            "expected_version": self.expected_version,
            "actual_version": self.actual_version,
        }


@dataclass
class DependencyVersionVerificationResult:
    valid: bool
    repository_root: str
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    mismatches: list[DependencyVersionMismatch] = field(
        default_factory=list
    )
    duplicates: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "repository_root": self.repository_root,
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "mismatches": [
                item.to_dict() for item in self.mismatches
            ],
            "duplicates": list(self.duplicates),
            "errors": list(self.errors),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2,
            sort_keys=True,
        )


@dataclass(frozen=True)
class DependencyVersionVerificationRequest:
    repository_root: Path
    expected: Sequence[ExpectedDependencyVersion]
    resolved: Sequence[ResolvedDependencyVersion]

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise DependencyVersionVerificationError(
                "repository_root must be a pathlib.Path"
            )

        if not self.repository_root.is_absolute():
            raise DependencyVersionVerificationError(
                "repository_root must be absolute"
            )


def _validate_repository_root(repository_root: Path) -> Path:
    if not isinstance(repository_root, Path):
        raise DependencyVersionVerificationError(
            "repository_root must be pathlib.Path"
        )

    if not repository_root.is_absolute():
        raise DependencyVersionVerificationError(
            "repository_root must be absolute"
        )

    try:
        resolved = repository_root.resolve(strict=True)
    except OSError as error:
        raise DependencyVersionVerificationError(
            f"Unable to resolve repository root: {repository_root}"
        ) from error

    if not resolved.is_dir():
        raise DependencyVersionVerificationError(
            f"Repository root is not a directory: {resolved}"
        )

    return resolved


def _build_map(
    dependencies: Sequence[
        ExpectedDependencyVersion | ResolvedDependencyVersion
    ],
) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    duplicates: list[str] = []

    for dependency in dependencies:
        name = normalize_name(dependency.name)
        version = dependency.version.strip()

        if name in values:
            if name not in duplicates:
                duplicates.append(name)
            continue

        values[name] = version

    return values, sorted(duplicates)


def verify_dependency_versions(
    request: DependencyVersionVerificationRequest,
) -> DependencyVersionVerificationResult:
    repository_root = _validate_repository_root(request.repository_root)

    errors: list[str] = []

    try:
        expected_map, expected_duplicates = _build_map(request.expected)
        resolved_map, resolved_duplicates = _build_map(request.resolved)
    except (TypeError, AttributeError, ValueError) as error:
        return DependencyVersionVerificationResult(
            valid=False,
            repository_root=str(repository_root),
            errors=[str(error)],
        )

    duplicates = sorted(
        set(expected_duplicates) | set(resolved_duplicates)
    )

    missing = sorted(
        set(expected_map) - set(resolved_map)
    )

    unexpected = sorted(
        set(resolved_map) - set(expected_map)
    )

    mismatches: list[DependencyVersionMismatch] = []

    for name in sorted(set(expected_map) & set(resolved_map)):
        expected_version = expected_map[name]
        actual_version = resolved_map[name]

        if expected_version != actual_version:
            mismatches.append(
                DependencyVersionMismatch(
                    name=name,
                    expected_version=expected_version,
                    actual_version=actual_version,
                )
            )

    valid = not any(
        (
            missing,
            unexpected,
            mismatches,
            duplicates,
            errors,
        )
    )

    return DependencyVersionVerificationResult(
        valid=valid,
        repository_root=str(repository_root),
        missing=missing,
        unexpected=unexpected,
        mismatches=mismatches,
        duplicates=duplicates,
        errors=errors,
    )


def validate_verification_result(
    result: DependencyVersionVerificationResult,
) -> bool:
    if not isinstance(
        result,
        DependencyVersionVerificationResult,
    ):
        return False

    if not isinstance(result.valid, bool):
        return False

    if not isinstance(result.repository_root, str):
        return False

    if not result.repository_root.strip():
        return False

    if result.missing:
        return False

    if result.unexpected:
        return False

    if result.mismatches:
        return False

    if result.duplicates:
        return False

    if result.errors:
        return False

    return result.valid is True
