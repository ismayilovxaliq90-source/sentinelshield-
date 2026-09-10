from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


class ManifestDiffAnalysisError(ValueError):
    """Raised when manifest diff analysis cannot be performed safely."""


_MAX_PATH_LENGTH = 4096
_MAX_DIFF_LENGTH = 2_000_000
_MAX_LINES = 100_000
_MAX_ITEMS = 10_000

_MANIFEST_FILENAMES = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "pyproject.toml": "python",
    "poetry.lock": "poetry",
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "pipfile": "pipenv",
    "pipfile.lock": "pipenv",
    "go.mod": "go",
    "go.sum": "go",
    "cargo.toml": "cargo",
    "cargo.lock": "cargo",
    "composer.json": "composer",
    "composer.lock": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "packages.config": "nuget",
    "package.swift": "swift",
}

_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)(token|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
)

_VERSION_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    r"v?"
    r"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)"
    r"(?![A-Za-z0-9])"
)

_DEPENDENCY_PATTERN = re.compile(
    r"(?P<name>"
    r"@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"|[A-Za-z0-9_.-]+"
    r")"
    r"\s*(?:[=:]|@|\s+)\s*"
    r"(?P<version>"
    r"[v^~<>=]*\s*"
    r"\d+(?:\.\d+){0,2}"
    r"(?:[-+][0-9A-Za-z.-]+)?"
    r")"
)


def _redact(text: str) -> str:
    value = text

    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(
            lambda match: "<REDACTED>",
            value,
        )

    return value


def _normalize_path(value: str) -> str:
    if not isinstance(value, str):
        raise ManifestDiffAnalysisError("Path must be a string")

    value = value.strip()

    if not value:
        raise ManifestDiffAnalysisError("Path must not be empty")

    if len(value) > _MAX_PATH_LENGTH:
        raise ManifestDiffAnalysisError("Path is too long")

    if "\x00" in value:
        raise ManifestDiffAnalysisError("NULL character is not allowed")

    path = Path(value)

    if path.is_absolute():
        raise ManifestDiffAnalysisError(
            "Manifest path must be repository-relative"
        )

    if any(part == ".." for part in path.parts):
        raise ManifestDiffAnalysisError(
            "Parent traversal is not allowed"
        )

    if value == ".":
        raise ManifestDiffAnalysisError("Repository root is not a manifest")

    return value.replace("\\", "/")


def _repository_root(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise ManifestDiffAnalysisError(
            "Repository root must be a path"
        )

    try:
        root = Path(value).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ManifestDiffAnalysisError(
            "Unable to resolve repository root"
        ) from exc

    if not root.exists() or not root.is_dir():
        raise ManifestDiffAnalysisError(
            "Repository root is not a directory"
        )

    git_dir = root / ".git"

    if not git_dir.exists():
        raise ManifestDiffAnalysisError(
            "Repository does not contain .git"
        )

    if git_dir.is_symlink():
        raise ManifestDiffAnalysisError(
            ".git must not be a symlink"
        )

    return root


def _manifest_type(path: str) -> str | None:
    filename = Path(path).name.lower()
    return _MANIFEST_FILENAMES.get(filename)


def _validate_manifest_path(
    repository_root: Path,
    manifest_path: str,
) -> Path:
    normalized = _normalize_path(manifest_path)

    candidate = (repository_root / normalized).resolve()

    try:
        candidate.relative_to(repository_root)
    except ValueError as exc:
        raise ManifestDiffAnalysisError(
            "Manifest path escapes repository"
        ) from exc

    if candidate.exists() and candidate.is_symlink():
        raise ManifestDiffAnalysisError(
            "Symlink manifests are not allowed"
        )

    if candidate.exists() and not candidate.is_file():
        raise ManifestDiffAnalysisError(
            "Manifest path is not a regular file"
        )

    return candidate


def _parse_dependency_line(line: str) -> tuple[str, str] | None:
    match = _DEPENDENCY_PATTERN.search(line)

    if not match:
        return None

    name = match.group("name").strip()
    version = re.sub(r"\s+", "", match.group("version"))

    if not name or not version:
        return None

    return name, version


def _extract_version(value: str) -> str | None:
    match = _VERSION_PATTERN.search(value)

    if not match:
        return None

    return match.group(1)


def _is_dependency_context(line: str) -> bool:
    lowered = line.lower()

    dependency_markers = (
        "dependencies",
        "devdependencies",
        "optionaldependencies",
        "peerdependencies",
        "require",
        "require-dev",
        "requires",
        "requirement",
        "package",
        "version",
        "module",
        "go ",
        "cargo",
    )

    return any(marker in lowered for marker in dependency_markers)


@dataclass(frozen=True)
class ManifestDependencyChange:
    name: str
    old_version: str | None
    new_version: str | None
    change_type: str
    line_number: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ManifestDiffAnalysisError(
                "Dependency name must not be empty"
            )

        if self.change_type not in {
            "added",
            "removed",
            "updated",
            "unknown",
        }:
            raise ManifestDiffAnalysisError(
                "Invalid dependency change type"
            )

        if type(self.line_number) is not int or self.line_number < 1:
            raise ManifestDiffAnalysisError(
                "Invalid line number"
            )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "change_type": self.change_type,
            "line_number": self.line_number,
        }


@dataclass(frozen=True)
class ManifestDiff:
    path: str
    manager: str
    added_lines: tuple[str, ...] = field(default_factory=tuple)
    removed_lines: tuple[str, ...] = field(default_factory=tuple)
    dependency_changes: tuple[ManifestDependencyChange, ...] = field(
        default_factory=tuple
    )
    malformed: bool = False

    def __post_init__(self) -> None:
        normalized = _normalize_path(self.path)

        if not self.manager:
            raise ManifestDiffAnalysisError(
                "Manifest manager must not be empty"
            )

        if len(self.added_lines) + len(self.removed_lines) > _MAX_LINES:
            raise ManifestDiffAnalysisError(
                "Manifest diff contains too many lines"
            )

        if len(self.dependency_changes) > _MAX_ITEMS:
            raise ManifestDiffAnalysisError(
                "Too many dependency changes"
            )

        object.__setattr__(self, "path", normalized)

    @property
    def has_dependency_changes(self) -> bool:
        return bool(self.dependency_changes)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "manager": self.manager,
            "added_lines": [_redact(x) for x in self.added_lines],
            "removed_lines": [_redact(x) for x in self.removed_lines],
            "dependency_changes": [
                item.to_dict()
                for item in self.dependency_changes
            ],
            "malformed": self.malformed,
            "has_dependency_changes": self.has_dependency_changes,
        }


@dataclass(frozen=True)
class ManifestDiffAnalysisResult:
    repository_root: str
    manifests: tuple[ManifestDiff, ...] = field(default_factory=tuple)
    unrelated_files: tuple[str, ...] = field(default_factory=tuple)
    unsupported_manifests: tuple[str, ...] = field(default_factory=tuple)
    malformed_manifests: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _normalize_path(self.repository_root)

        if len(self.manifests) > _MAX_ITEMS:
            raise ManifestDiffAnalysisError(
                "Too many manifests"
            )

        for path in self.unrelated_files:
            _normalize_path(path)

        for path in self.unsupported_manifests:
            _normalize_path(path)

        for path in self.malformed_manifests:
            _normalize_path(path)

    @property
    def changed_manifest_count(self) -> int:
        return len(self.manifests)

    @property
    def dependency_change_count(self) -> int:
        return sum(
            len(item.dependency_changes)
            for item in self.manifests
        )

    @property
    def has_dependency_changes(self) -> bool:
        return self.dependency_change_count > 0

    @property
    def is_safe(self) -> bool:
        return not self.malformed_manifests

    def to_dict(self) -> dict:
        return {
            "repository_root": self.repository_root,
            "manifests": [
                item.to_dict()
                for item in self.manifests
            ],
            "unrelated_files": list(self.unrelated_files),
            "unsupported_manifests": list(self.unsupported_manifests),
            "malformed_manifests": list(self.malformed_manifests),
            "changed_manifest_count": self.changed_manifest_count,
            "dependency_change_count": self.dependency_change_count,
            "has_dependency_changes": self.has_dependency_changes,
            "is_safe": self.is_safe,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            indent=2,
        )


def _parse_manifest_hunks(
    path: str,
    manager: str,
    diff_text: str,
) -> ManifestDiff:
    added: list[str] = []
    removed: list[str] = []

    current_line = 0
    malformed = False

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            match = re.search(
                r"\+(\d+)(?:,\d+)?",
                raw_line,
            )

            if match:
                current_line = int(match.group(1))

            continue

        if raw_line.startswith("+++"):
            continue

        if raw_line.startswith("---"):
            continue

        if raw_line.startswith("+"):
            text = raw_line[1:]
            added.append(text)
            current_line += 1
            continue

        if raw_line.startswith("-"):
            removed.append(raw_line[1:])
            continue

        if raw_line.startswith(" "):
            current_line += 1

    if len(added) + len(removed) > _MAX_LINES:
        malformed = True

    dependency_changes: list[ManifestDependencyChange] = []

    # Pair removed and added dependency lines by dependency name.
    removed_dependencies: dict[str, list[tuple[str, int]]] = {}
    added_dependencies: dict[str, list[tuple[str, int]]] = {}

    for index, line in enumerate(removed, start=1):
        parsed = _parse_dependency_line(line)

        if parsed and _is_dependency_context(line):
            removed_dependencies.setdefault(
                parsed[0],
                [],
            ).append((parsed[1], index))

    for index, line in enumerate(added, start=1):
        parsed = _parse_dependency_line(line)

        if parsed and _is_dependency_context(line):
            added_dependencies.setdefault(
                parsed[0],
                [],
            ).append((parsed[1], index))

    all_names = set(removed_dependencies) | set(added_dependencies)

    for name in sorted(all_names):
        old_values = removed_dependencies.get(name, [])
        new_values = added_dependencies.get(name, [])

        pair_count = min(len(old_values), len(new_values))

        for index in range(pair_count):
            old_version = old_values[index][0]
            new_version = new_values[index][0]

            if old_version == new_version:
                continue

            dependency_changes.append(
                ManifestDependencyChange(
                    name=name,
                    old_version=old_version,
                    new_version=new_version,
                    change_type="updated",
                    line_number=new_values[index][1],
                )
            )

        for version, line_number in old_values[pair_count:]:
            dependency_changes.append(
                ManifestDependencyChange(
                    name=name,
                    old_version=version,
                    new_version=None,
                    change_type="removed",
                    line_number=line_number,
                )
            )

        for version, line_number in new_values[pair_count:]:
            dependency_changes.append(
                ManifestDependencyChange(
                    name=name,
                    old_version=None,
                    new_version=version,
                    change_type="added",
                    line_number=line_number,
                )
            )

    return ManifestDiff(
        path=path,
        manager=manager,
        added_lines=tuple(_redact(x) for x in added),
        removed_lines=tuple(_redact(x) for x in removed),
        dependency_changes=tuple(dependency_changes),
        malformed=malformed,
    )


def analyze_manifest_diff(
    repository_root: str | Path,
    diff: str,
    manifest_paths: Iterable[str],
) -> ManifestDiffAnalysisResult:
    root = _repository_root(repository_root)

    if not isinstance(diff, str):
        raise ManifestDiffAnalysisError(
            "Diff must be a string"
        )

    if len(diff) > _MAX_DIFF_LENGTH:
        raise ManifestDiffAnalysisError(
            "Diff exceeds safety limit"
        )

    try:
        paths = list(manifest_paths)
    except TypeError as exc:
        raise ManifestDiffAnalysisError(
            "Manifest paths must be iterable"
        ) from exc

    if len(paths) > _MAX_ITEMS:
        raise ManifestDiffAnalysisError(
            "Too many manifest paths"
        )

    normalized_paths: list[str] = []
    seen: set[str] = set()

    for path in paths:
        normalized = _normalize_path(path)

        if normalized in seen:
            continue

        seen.add(normalized)
        normalized_paths.append(normalized)

    manifests: list[ManifestDiff] = []
    unsupported: list[str] = []
    malformed: list[str] = []

    diff_lines = diff.splitlines()

    for path in normalized_paths:
        manager = _manifest_type(path)

        if manager is None:
            unsupported.append(path)
            continue

        _validate_manifest_path(root, path)

        prefix = f"+++ b/{path}"
        start = None

        for index, line in enumerate(diff_lines):
            if line == prefix:
                start = index
                break

        if start is None:
            # Try a normal diff header in case the path was deleted.
            old_prefix = f"--- a/{path}"

            for index, line in enumerate(diff_lines):
                if line == old_prefix:
                    start = index
                    break

        if start is None:
            # The caller may have explicitly supplied the manifest while
            # the diff contains no entry for it.
            continue

        block: list[str] = []

        for line in diff_lines[start:]:
            if (
                block
                and line.startswith("diff --git ")
            ):
                break

            block.append(line)

        manifest_diff = _parse_manifest_hunks(
            path,
            manager,
            "\n".join(block),
        )

        manifests.append(manifest_diff)

        if manifest_diff.malformed:
            malformed.append(path)

    changed_paths: set[str] = set()

    for line in diff_lines:
        if line.startswith("+++ b/"):
            changed_paths.add(line[6:])
        elif line.startswith("--- a/"):
            changed_paths.add(line[6:])

    unrelated = sorted(
        path
        for path in changed_paths
        if path not in seen
    )

    return ManifestDiffAnalysisResult(
        repository_root=str(root),
        manifests=tuple(manifests),
        unrelated_files=tuple(unrelated),
        unsupported_manifests=tuple(sorted(set(unsupported))),
        malformed_manifests=tuple(sorted(set(malformed))),
    )


def validate_manifest_diff_analysis(
    result: ManifestDiffAnalysisResult,
) -> bool:
    if not isinstance(result, ManifestDiffAnalysisResult):
        return False

    try:
        ManifestDiffAnalysisResult(
            repository_root=result.repository_root,
            manifests=result.manifests,
            unrelated_files=result.unrelated_files,
            unsupported_manifests=result.unsupported_manifests,
            malformed_manifests=result.malformed_manifests,
        )
    except (ManifestDiffAnalysisError, TypeError, ValueError):
        return False

    return True


# Explicit aliases for Task 217 callers.
analyze_manifest_diffs = analyze_manifest_diff
validate_manifest_diff = validate_manifest_diff_analysis
