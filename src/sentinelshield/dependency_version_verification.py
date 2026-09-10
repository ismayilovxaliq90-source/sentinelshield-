from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import re


class DependencyVersionVerificationError(Exception):
    """Raised when dependency-version verification input is invalid."""


@dataclass(frozen=True)
class ResolvedDependencyVersion:
    name: str
    version: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("dependency name must be non-empty")

        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("dependency version must be non-empty")

        if not is_valid_version(self.version):
            raise ValueError(
                f"invalid dependency version: {self.version}"
            )

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.name)

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
        }


@dataclass(frozen=True)
class ExpectedDependencyVersion:
    name: str
    expected_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("dependency name must be non-empty")

        if not isinstance(self.expected_version, str):
            raise TypeError("expected_version must be string")

        if not self.expected_version.strip():
            raise ValueError("expected_version must be non-empty")

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.name)

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "expected_version": self.expected_version,
        }


@dataclass(frozen=True)
class DependencyVersionMismatch:
    name: str
    expected_version: str
    actual_version: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "expected_version": self.expected_version,
            "actual_version": self.actual_version,
        }


@dataclass(frozen=True)
class DependencyVersionVerificationResult:
    valid: bool
    reason: str
    verified: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    mismatches: tuple[DependencyVersionMismatch, ...] = ()
    unexpected: tuple[str, ...] = ()
    duplicates: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "verified": list(self.verified),
            "missing": list(self.missing),
            "mismatches": [
                mismatch.to_dict()
                for mismatch in self.mismatches
            ],
            "unexpected": list(self.unexpected),
            "duplicates": list(self.duplicates),
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
    resolved_dependencies: tuple[ResolvedDependencyVersion, ...]
    expected_dependencies: tuple[ExpectedDependencyVersion, ...]
    package_manager: str = "unknown"

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise TypeError("repository_root must be pathlib.Path")

        allowed_managers = {
            "npm",
            "pnpm",
            "yarn",
            "pip",
            "poetry",
            "cargo",
            "go",
            "composer",
            "unknown",
        }

        if self.package_manager not in allowed_managers:
            raise ValueError(
                f"unsupported package manager: {self.package_manager}"
            )

        for dependency in self.resolved_dependencies:
            if not isinstance(dependency, ResolvedDependencyVersion):
                raise TypeError(
                    "resolved_dependencies must contain "
                    "ResolvedDependencyVersion values"
                )

        for dependency in self.expected_dependencies:
            if not isinstance(dependency, ExpectedDependencyVersion):
                raise TypeError(
                    "expected_dependencies must contain "
                    "ExpectedDependencyVersion values"
                )


def normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("dependency name must be string")

    normalized = name.strip().lower()
    normalized = re.sub(r"\s+", "-", normalized)

    if not normalized:
        raise ValueError("dependency name must be non-empty")

    return normalized


def is_valid_version(version: str) -> bool:
    if not isinstance(version, str):
        return False

    value = version.strip()

    if value.startswith(("v", "V")):
        value = value[1:]

    # Supports normal semantic versions and prerelease/build metadata.
    pattern = (
        r"^(0|[1-9]\d*)"
        r"\.(0|[1-9]\d*)"
        r"\.(0|[1-9]\d*)"
        r"(?:-[0-9A-Za-z.-]+)?"
        r"(?:\+[0-9A-Za-z.-]+)?$"
    )

    return re.fullmatch(pattern, value) is not None


def _validate_repository(root: Path) -> Path:
    try:
        resolved = root.expanduser().resolve()
    except OSError as error:
        raise DependencyVersionVerificationError(
            "unable to resolve repository root"
        ) from error

    if not resolved.exists():
        raise DependencyVersionVerificationError(
            f"repository does not exist: {resolved}"
        )

    if not resolved.is_dir():
        raise DependencyVersionVerificationError(
            f"repository is not a directory: {resolved}"
        )

    if not (resolved / ".git").exists():
        raise DependencyVersionVerificationError(
            f"not a git repository: {resolved}"
        )

    return resolved


def _duplicates(
    dependencies: tuple[ResolvedDependencyVersion, ...],
) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()

    for dependency in dependencies:
        name = dependency.normalized_name

        if name in seen:
            duplicates.add(name)
        else:
            seen.add(name)

    return tuple(sorted(duplicates))


def _map_resolved(
    dependencies: tuple[ResolvedDependencyVersion, ...],
) -> dict[str, ResolvedDependencyVersion]:
    return {
        dependency.normalized_name: dependency
        for dependency in dependencies
    }


def _map_expected(
    dependencies: tuple[ExpectedDependencyVersion, ...],
) -> dict[str, ExpectedDependencyVersion]:
    result: dict[str, ExpectedDependencyVersion] = {}

    for dependency in dependencies:
        name = dependency.normalized_name

        if name in result:
            raise DependencyVersionVerificationError(
                f"duplicate expected dependency: {name}"
            )

        result[name] = dependency

    return result


def verify_dependency_versions(
    request: DependencyVersionVerificationRequest,
) -> DependencyVersionVerificationResult:
    _validate_repository(request.repository_root)

    duplicate_resolved = _duplicates(
        request.resolved_dependencies
    )

    if duplicate_resolved:
        return DependencyVersionVerificationResult(
            valid=False,
            reason="DUPLICATE_RESOLVED_DEPENDENCY",
            duplicates=duplicate_resolved,
        )

    resolved = _map_resolved(
        request.resolved_dependencies
    )

    expected = _map_expected(
        request.expected_dependencies
    )

    missing: list[str] = []
    mismatches: list[DependencyVersionMismatch] = []
    verified: list[str] = []

    for name in sorted(expected):
        expected_dependency = expected[name]
        actual = resolved.get(name)

        if actual is None:
            missing.append(expected_dependency.name)
            continue

        if actual.version != expected_dependency.expected_version:
            mismatches.append(
                DependencyVersionMismatch(
                    name=expected_dependency.name,
                    expected_version=expected_dependency.expected_version,
                    actual_version=actual.version,
                )
            )
            continue

        verified.append(expected_dependency.name)

    unexpected = sorted(set(resolved) - set(expected))

    if missing:
        return DependencyVersionVerificationResult(
            valid=False,
            reason="DEPENDENCY_VERSION_MISSING",
            verified=tuple(sorted(verified)),
            missing=tuple(sorted(missing)),
            mismatches=tuple(mismatches),
            unexpected=tuple(unexpected),
        )

    if mismatches:
        return DependencyVersionVerificationResult(
            valid=False,
            reason="DEPENDENCY_VERSION_MISMATCH",
            verified=tuple(sorted(verified)),
            mismatches=tuple(mismatches),
            unexpected=tuple(unexpected),
        )

    if unexpected:
        return DependencyVersionVerificationResult(
            valid=False,
            reason="UNEXPECTED_DEPENDENCY",
            verified=tuple(sorted(verified)),
            unexpected=tuple(unexpected),
        )

    return DependencyVersionVerificationResult(
        valid=True,
        reason="DEPENDENCY_VERSIONS_VERIFIED",
        verified=tuple(sorted(verified)),
    )


def validate_verification_result(
    result: DependencyVersionVerificationResult,
) -> bool:
    return (
        result.valid
        and not result.missing
        and not result.mismatches
        and not result.unexpected
        and not result.duplicates
    )
