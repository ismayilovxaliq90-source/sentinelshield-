from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping


class DependencyVersionVerificationError(RuntimeError):
    """Raised when dependency version verification cannot be performed safely."""


VERSION_PATTERN = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?$"
)

SUPPORTED_MANAGERS = frozenset(
    {
        "npm",
        "pnpm",
        "yarn",
        "go",
        "cargo",
        "composer",
        "poetry",
    }
)


@dataclass(frozen=True)
class ExpectedDependency:
    name: str
    version: str
    direct: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "direct": self.direct,
        }


@dataclass(frozen=True)
class ActualDependency:
    name: str
    version: str
    source: str = "dependency_tree"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
        }


@dataclass(frozen=True)
class DependencyVersionMismatch:
    name: str
    expected: tuple[str, ...]
    actual: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "expected": list(self.expected),
            "actual": list(self.actual),
        }


@dataclass(frozen=True)
class DependencyVersionVerificationResult:
    success: bool
    manager: str
    verified: tuple[ActualDependency, ...]
    missing: tuple[str, ...]
    unexpected: tuple[str, ...]
    mismatches: tuple[DependencyVersionMismatch, ...]
    duplicate_versions: Mapping[str, tuple[str, ...]]
    errors: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "manager": self.manager,
            "verified": [
                item.to_dict()
                for item in self.verified
            ],
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "mismatches": [
                item.to_dict()
                for item in self.mismatches
            ],
            "duplicate_versions": {
                name: list(versions)
                for name, versions in self.duplicate_versions.items()
            },
            "errors": list(self.errors),
        }


def _normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise DependencyVersionVerificationError(
            "Dependency name must be a string"
        )

    value = name.strip()

    if not value:
        raise DependencyVersionVerificationError(
            "Dependency name cannot be empty"
        )

    if "\x00" in value:
        raise DependencyVersionVerificationError(
            "Dependency name contains NULL character"
        )

    return value


def normalize_version(version: str) -> str:
    if not isinstance(version, str):
        raise DependencyVersionVerificationError(
            "Dependency version must be a string"
        )

    value = version.strip()

    if not value:
        raise DependencyVersionVerificationError(
            "Dependency version cannot be empty"
        )

    if "\x00" in value:
        raise DependencyVersionVerificationError(
            "Dependency version contains NULL character"
        )

    # Verification intentionally accepts common leading
    # semantic-version syntax but removes only harmless whitespace.
    if value.startswith(("v", "V")):
        value = value[1:]

    if not VERSION_PATTERN.fullmatch(value):
        raise DependencyVersionVerificationError(
            f"Invalid dependency version: {version}"
        )

    return value


def normalize_expected_dependencies(
    dependencies: Iterable[ExpectedDependency],
) -> tuple[ExpectedDependency, ...]:
    if dependencies is None:
        raise DependencyVersionVerificationError(
            "Expected dependencies cannot be None"
        )

    normalized: list[ExpectedDependency] = []
    seen: set[tuple[str, str, bool]] = set()

    for dependency in dependencies:
        if not isinstance(dependency, ExpectedDependency):
            raise DependencyVersionVerificationError(
                "Invalid expected dependency"
            )

        name = _normalize_name(dependency.name)
        version = normalize_version(dependency.version)

        item = ExpectedDependency(
            name=name,
            version=version,
            direct=bool(dependency.direct),
        )

        key = (
            item.name,
            item.version,
            item.direct,
        )

        if key not in seen:
            normalized.append(item)
            seen.add(key)

    return tuple(normalized)


def normalize_actual_dependencies(
    dependencies: Iterable[ActualDependency],
) -> tuple[ActualDependency, ...]:
    if dependencies is None:
        raise DependencyVersionVerificationError(
            "Actual dependencies cannot be None"
        )

    normalized: list[ActualDependency] = []
    seen: set[tuple[str, str, str]] = set()

    for dependency in dependencies:
        if not isinstance(dependency, ActualDependency):
            raise DependencyVersionVerificationError(
                "Invalid actual dependency"
            )

        name = _normalize_name(dependency.name)
        version = normalize_version(dependency.version)

        source = dependency.source.strip()

        if not source:
            raise DependencyVersionVerificationError(
                "Dependency source cannot be empty"
            )

        item = ActualDependency(
            name=name,
            version=version,
            source=source,
        )

        key = (
            item.name,
            item.version,
            item.source,
        )

        if key not in seen:
            normalized.append(item)
            seen.add(key)

    return tuple(normalized)


def _validate_repository_root(
    repository_root: Path,
) -> Path:
    if not isinstance(repository_root, Path):
        raise DependencyVersionVerificationError(
            "repository_root must be a Path"
        )

    try:
        root = repository_root.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DependencyVersionVerificationError(
            f"Unable to resolve repository root: {repository_root}"
        ) from exc

    if not root.is_dir():
        raise DependencyVersionVerificationError(
            f"Repository root is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise DependencyVersionVerificationError(
            f"Not a Git repository: {root}"
        )

    return root


def validate_manifest_path(
    repository_root: Path,
    manifest_path: Path,
) -> Path:
    root = _validate_repository_root(repository_root)

    if not isinstance(manifest_path, Path):
        raise DependencyVersionVerificationError(
            "manifest_path must be a Path"
        )

    if manifest_path.is_symlink():
        raise DependencyVersionVerificationError(
            f"Manifest symlink is not allowed: {manifest_path}"
        )

    try:
        resolved = manifest_path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DependencyVersionVerificationError(
            f"Unable to resolve manifest: {manifest_path}"
        ) from exc

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise DependencyVersionVerificationError(
            f"Manifest escapes repository root: {manifest_path}"
        ) from exc

    if not resolved.is_file():
        raise DependencyVersionVerificationError(
            f"Manifest is not a regular file: {resolved}"
        )

    return resolved


def validate_manager(manager: str) -> str:
    if not isinstance(manager, str):
        raise DependencyVersionVerificationError(
            "manager must be a string"
        )

    normalized = manager.strip().lower()

    if normalized not in SUPPORTED_MANAGERS:
        raise DependencyVersionVerificationError(
            f"Unsupported package manager: {manager}"
        )

    return normalized


def _versions_by_name(
    dependencies: Iterable[ActualDependency],
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}

    for dependency in dependencies:
        result.setdefault(dependency.name, set()).add(
            dependency.version
        )

    return result


def verify_dependency_versions(
    *,
    manager: str,
    expected: Iterable[ExpectedDependency],
    actual: Iterable[ActualDependency],
) -> DependencyVersionVerificationResult:
    normalized_manager = validate_manager(manager)

    expected_items = normalize_expected_dependencies(expected)
    actual_items = normalize_actual_dependencies(actual)

    expected_by_name: dict[str, set[str]] = {}

    for dependency in expected_items:
        expected_by_name.setdefault(
            dependency.name,
            set(),
        ).add(dependency.version)

    actual_by_name = _versions_by_name(actual_items)

    missing: list[str] = []
    unexpected: list[str] = []
    mismatches: list[DependencyVersionMismatch] = []
    verified: list[ActualDependency] = []

    for name in sorted(expected_by_name):
        expected_versions = expected_by_name[name]
        actual_versions = actual_by_name.get(name, set())

        if not actual_versions:
            missing.append(name)
            continue

        if expected_versions.isdisjoint(actual_versions):
            mismatches.append(
                DependencyVersionMismatch(
                    name=name,
                    expected=tuple(sorted(expected_versions)),
                    actual=tuple(sorted(actual_versions)),
                )
            )
            continue

        for dependency in actual_items:
            if (
                dependency.name == name
                and dependency.version in expected_versions
            ):
                verified.append(dependency)

    for name in sorted(actual_by_name):
        if name not in expected_by_name:
            unexpected.append(name)

    duplicates = {
        name: tuple(sorted(versions))
        for name, versions in sorted(actual_by_name.items())
        if len(versions) > 1
    }

    errors: list[str] = []

    if missing:
        errors.append("MISSING_DEPENDENCIES")

    if unexpected:
        errors.append("UNEXPECTED_DEPENDENCIES")

    if mismatches:
        errors.append("DEPENDENCY_VERSION_MISMATCH")

    success = not errors

    return DependencyVersionVerificationResult(
        success=success,
        manager=normalized_manager,
        verified=tuple(verified),
        missing=tuple(missing),
        unexpected=tuple(unexpected),
        mismatches=tuple(mismatches),
        duplicate_versions=duplicates,
        errors=tuple(errors),
    )


def validate_verification_result(
    result: DependencyVersionVerificationResult,
) -> bool:
    if not isinstance(
        result,
        DependencyVersionVerificationResult,
    ):
        return False

    if result.manager not in SUPPORTED_MANAGERS:
        return False

    for dependency in result.verified:
        if not isinstance(dependency, ActualDependency):
            return False

        try:
            _normalize_name(dependency.name)
            normalize_version(dependency.version)
        except DependencyVersionVerificationError:
            return False

    if result.success:
        if result.missing:
            return False
        if result.unexpected:
            return False
        if result.mismatches:
            return False
        if result.errors:
            return False

    return True


def verify_repository_manifest(
    repository_root: Path,
    manifest_path: Path,
    manager: str,
    expected: Iterable[ExpectedDependency],
    actual: Iterable[ActualDependency],
) -> DependencyVersionVerificationResult:
    validate_manifest_path(
        repository_root,
        manifest_path,
    )

    return verify_dependency_versions(
        manager=manager,
        expected=expected,
        actual=actual,
    )


__all__ = [
    "DependencyVersionVerificationError",
    "ExpectedDependency",
    "ActualDependency",
    "DependencyVersionMismatch",
    "DependencyVersionVerificationResult",
    "SUPPORTED_MANAGERS",
    "normalize_version",
    "normalize_expected_dependencies",
    "normalize_actual_dependencies",
    "validate_manifest_path",
    "validate_manager",
    "verify_dependency_versions",
    "validate_verification_result",
    "verify_repository_manifest",
]
