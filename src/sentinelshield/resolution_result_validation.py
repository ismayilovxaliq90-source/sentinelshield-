from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import re
from typing import Mapping


class ResolutionValidationError(Exception):
    """Raised when a dependency-resolution result is invalid."""


@dataclass(frozen=True)
class ResolvedDependency:
    name: str
    version: str
    direct: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("dependency name must be non-empty")

        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("dependency version must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "direct": self.direct,
        }


@dataclass(frozen=True)
class ResolutionResult:
    success: bool
    exit_code: int | None
    timed_out: bool
    dependencies: tuple[ResolvedDependency, ...] = field(default_factory=tuple)
    stdout: str = ""
    stderr: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "dependencies": [
                dependency.to_dict()
                for dependency in self.dependencies
            ],
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass(frozen=True)
class ExpectedDependency:
    name: str
    version_constraint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("expected dependency name must be non-empty")

        if self.version_constraint is not None:
            if (
                not isinstance(self.version_constraint, str)
                or not self.version_constraint.strip()
            ):
                raise ValueError(
                    "version constraint must be non-empty when supplied"
                )

    def to_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "version_constraint": self.version_constraint,
        }


@dataclass(frozen=True)
class ResolutionValidationResult:
    valid: bool
    reason: str
    missing_dependencies: tuple[str, ...] = ()
    version_mismatches: tuple[str, ...] = ()
    duplicate_dependencies: tuple[str, ...] = ()
    resolved_count: int = 0
    expected_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "missing_dependencies": list(self.missing_dependencies),
            "version_mismatches": list(self.version_mismatches),
            "duplicate_dependencies": list(self.duplicate_dependencies),
            "resolved_count": self.resolved_count,
            "expected_count": self.expected_count,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass(frozen=True)
class ResolutionValidationRequest:
    repository_root: Path
    result: ResolutionResult
    expected_dependencies: tuple[ExpectedDependency, ...] = ()
    package_manager: str = "unknown"

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise TypeError("repository_root must be pathlib.Path")

        if not isinstance(self.result, ResolutionResult):
            raise TypeError("result must be ResolutionResult")

        if self.package_manager not in {
            "npm",
            "pnpm",
            "yarn",
            "pip",
            "poetry",
            "cargo",
            "go",
            "composer",
            "unknown",
        }:
            raise ValueError(
                f"unsupported package manager: {self.package_manager}"
            )

        for dependency in self.expected_dependencies:
            if not isinstance(dependency, ExpectedDependency):
                raise TypeError(
                    "expected_dependencies must contain "
                    "ExpectedDependency values"
                )


def validate_repository_root(repository_root: Path) -> Path:
    if not isinstance(repository_root, Path):
        raise TypeError("repository_root must be pathlib.Path")

    try:
        root = repository_root.expanduser().resolve()
    except OSError as error:
        raise ResolutionValidationError(
            "unable to resolve repository root"
        ) from error

    if not root.exists():
        raise ResolutionValidationError(
            f"repository does not exist: {root}"
        )

    if not root.is_dir():
        raise ResolutionValidationError(
            f"repository is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise ResolutionValidationError(
            f"not a git repository: {root}"
        )

    return root


def _normalise_name(name: str) -> str:
    return re.sub(r"\s+", "-", name.strip().lower())


def detect_duplicates(
    dependencies: tuple[ResolvedDependency, ...],
) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()

    for dependency in dependencies:
        normalized = _normalise_name(dependency.name)

        if normalized in seen:
            duplicates.add(normalized)
        else:
            seen.add(normalized)

    return tuple(sorted(duplicates))


def _version_tuple(version: str) -> tuple[int, ...] | None:
    cleaned = version.strip()
    if cleaned.startswith(("v", "V")):
        cleaned = cleaned[1:]

    match = re.match(r"^(\d+(?:\.\d+)*)", cleaned)

    if not match:
        return None

    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def version_satisfies(version: str, constraint: str | None) -> bool:
    if constraint is None:
        return True

    version_value = _version_tuple(version)
    if version_value is None:
        return False

    expression = constraint.strip()

    if expression in {"*", "latest"}:
        return True

    # Simple exact version.
    if re.fullmatch(r"v?\d+(?:\.\d+){0,2}", expression):
        expected = _version_tuple(expression)
        return expected == version_value

    # Basic >=, <=, > and < support.
    match = re.fullmatch(
        r"(>=|<=|>|<)\s*v?(\d+(?:\.\d+){0,2})",
        expression,
    )

    if match:
        operator = match.group(1)
        expected = _version_tuple(match.group(2))

        if expected is None:
            return False

        width = max(len(version_value), len(expected))
        actual = version_value + (0,) * (width - len(version_value))
        target = expected + (0,) * (width - len(expected))

        if operator == ">=":
            return actual >= target
        if operator == "<=":
            return actual <= target
        if operator == ">":
            return actual > target
        if operator == "<":
            return actual < target

    # Basic caret compatibility.
    if expression.startswith("^"):
        expected = _version_tuple(expression[1:])

        if expected is None:
            return False

        if len(expected) == 0:
            return False

        if expected[0] > 0:
            return (
                version_value >= expected
                and version_value[0] == expected[0]
            )

        if len(expected) > 1 and expected[1] > 0:
            return (
                version_value >= expected
                and version_value[:2] == expected[:2]
            )

        if len(expected) > 2:
            return (
                version_value >= expected
                and version_value[:3] == expected[:3]
            )

        return False

    # Basic tilde compatibility.
    if expression.startswith("~"):
        expected = _version_tuple(expression[1:])

        if expected is None:
            return False

        if len(expected) == 1:
            return (
                version_value >= expected
                and version_value[0] == expected[0]
            )

        return (
            version_value >= expected
            and version_value[:2] == expected[:2]
        )

    return False


def validate_resolution_result(
    request: ResolutionValidationRequest,
) -> ResolutionValidationResult:
    validate_repository_root(request.repository_root)

    result = request.result

    if not result.success:
        return ResolutionValidationResult(
            valid=False,
            reason="RESOLUTION_FAILED",
            resolved_count=len(result.dependencies),
            expected_count=len(request.expected_dependencies),
        )

    if result.timed_out:
        return ResolutionValidationResult(
            valid=False,
            reason="RESOLUTION_TIMEOUT",
            resolved_count=len(result.dependencies),
            expected_count=len(request.expected_dependencies),
        )

    if result.exit_code != 0:
        return ResolutionValidationResult(
            valid=False,
            reason="NON_ZERO_EXIT_CODE",
            resolved_count=len(result.dependencies),
            expected_count=len(request.expected_dependencies),
        )

    if result.error:
        return ResolutionValidationResult(
            valid=False,
            reason="RESOLUTION_ERROR_PRESENT",
            resolved_count=len(result.dependencies),
            expected_count=len(request.expected_dependencies),
        )

    duplicate_dependencies = detect_duplicates(result.dependencies)

    resolved_by_name = {
        _normalise_name(dependency.name): dependency
        for dependency in result.dependencies
    }

    missing: list[str] = []
    mismatches: list[str] = []

    for expected in request.expected_dependencies:
        normalized = _normalise_name(expected.name)
        resolved = resolved_by_name.get(normalized)

        if resolved is None:
            missing.append(expected.name)
            continue

        if not version_satisfies(
            resolved.version,
            expected.version_constraint,
        ):
            mismatches.append(
                f"{expected.name}: "
                f"{resolved.version} does not satisfy "
                f"{expected.version_constraint}"
            )

    if duplicate_dependencies:
        return ResolutionValidationResult(
            valid=False,
            reason="DUPLICATE_DEPENDENCIES",
            missing_dependencies=tuple(sorted(missing)),
            version_mismatches=tuple(sorted(mismatches)),
            duplicate_dependencies=duplicate_dependencies,
            resolved_count=len(result.dependencies),
            expected_count=len(request.expected_dependencies),
        )

    if missing:
        return ResolutionValidationResult(
            valid=False,
            reason="MISSING_DEPENDENCIES",
            missing_dependencies=tuple(sorted(missing)),
            version_mismatches=tuple(sorted(mismatches)),
            resolved_count=len(result.dependencies),
            expected_count=len(request.expected_dependencies),
        )

    if mismatches:
        return ResolutionValidationResult(
            valid=False,
            reason="VERSION_MISMATCH",
            version_mismatches=tuple(sorted(mismatches)),
            resolved_count=len(result.dependencies),
            expected_count=len(request.expected_dependencies),
        )

    return ResolutionValidationResult(
        valid=True,
        reason="RESOLUTION_VALID",
        resolved_count=len(result.dependencies),
        expected_count=len(request.expected_dependencies),
    )
