from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MAX_PATH_LENGTH = 4096
MAX_DIFF_LENGTH = 2_000_000
MAX_ITEMS = 10_000

SUPPORTED_MANIFESTS = {
    "package.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "pnpm-workspace.yaml": "pnpm",
    "yarn.lock": "yarn",
    "pyproject.toml": "python",
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "poetry.lock": "poetry",
    "go.mod": "go",
    "Cargo.toml": "cargo",
    "composer.json": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "packages.config": "nuget",
    "Package.swift": "swift",
}

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|"
        r"access[_-]?key|private[_-]?key)"
        r"(\s*[:=]\s*)(['\"]?)[^'\"\s,}]+"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
)

_JSON_DEP_PATTERN = re.compile(
    r'"(?P<name>@?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)"'
    r'\s*:\s*"(?P<version>[^"]+)"'
)

_PYTHON_DEP_PATTERN = re.compile(
    r"(?P<name>[A-Za-z0-9_.-]+)"
    r"\s*(?P<operator>===|==|>=|<=|~=|>|<)"
    r"\s*(?P<version>[0-9]+(?:\.[0-9A-Za-z*+_-]+){1,5}"
    r"(?:[-+][0-9A-Za-z._-]+)?)"
)

_DIFF_FILE_PATTERN = re.compile(
    r"^diff --git a/(?P<a>\S+) b/(?P<b>\S+)$"
)

_HUNK_PATTERN = re.compile(
    r"^@@(?: -\d+(?:,\d+)?)+ "
    r"\+(?P<new>\d+)(?:,\d+)? @@"
)

_NULL = "\x00"


class ManifestDiffAnalysisError(ValueError):
    """Invalid manifest diff analysis input."""


def _validate_text(
    value: object,
    name: str,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise ManifestDiffAnalysisError(
            f"{name} must be a string"
        )

    if not value:
        raise ManifestDiffAnalysisError(
            f"{name} must not be empty"
        )

    if _NULL in value:
        raise ManifestDiffAnalysisError(
            f"{name} contains a NULL character"
        )

    if len(value) > maximum:
        raise ManifestDiffAnalysisError(
            f"{name} is too long"
        )

    return value


def _normalize_relative_path(value: object) -> str:
    value = _validate_text(
        value,
        "Manifest path",
        MAX_PATH_LENGTH,
    ).strip()

    if not value:
        raise ManifestDiffAnalysisError(
            "Manifest path must not be empty"
        )

    path = Path(value)

    if path.is_absolute():
        raise ManifestDiffAnalysisError(
            "Manifest path must be repository-relative"
        )

    normalized = value.replace("\\", "/")

    if normalized in {".", "./"}:
        raise ManifestDiffAnalysisError(
            "Manifest path must not be repository root"
        )

    parts = normalized.split("/")

    if any(part in {"", ".", ".."} for part in parts):
        raise ManifestDiffAnalysisError(
            "Manifest path contains an unsafe component"
        )

    return "/".join(parts)


def _validate_repository_root(
    value: object,
) -> Path:
    if not isinstance(value, (str, Path)):
        raise ManifestDiffAnalysisError(
            "Repository root must be a string or Path"
        )

    try:
        root = Path(value).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ManifestDiffAnalysisError(
            "Unable to resolve repository root"
        ) from exc

    if not root.is_absolute():
        raise ManifestDiffAnalysisError(
            "Repository root must be absolute"
        )

    if not root.exists():
        raise ManifestDiffAnalysisError(
            "Repository root does not exist"
        )

    if not root.is_dir():
        raise ManifestDiffAnalysisError(
            "Repository root is not a directory"
        )

    if root.is_symlink():
        raise ManifestDiffAnalysisError(
            "Repository root must not be a symlink"
        )

    return root


def _normalize_manifest_paths(
    manifests: Iterable[str],
) -> tuple[str, ...]:
    if isinstance(manifests, (str, bytes)):
        raise ManifestDiffAnalysisError(
            "Manifests must be an iterable of paths"
        )

    try:
        values = list(manifests)
    except TypeError as exc:
        raise ManifestDiffAnalysisError(
            "Manifests must be iterable"
        ) from exc

    if len(values) > MAX_ITEMS:
        raise ManifestDiffAnalysisError(
            "Too many manifest paths"
        )

    result = tuple(
        _normalize_relative_path(item)
        for item in values
    )

    if len(set(result)) != len(result):
        raise ManifestDiffAnalysisError(
            "Duplicate manifest paths are not allowed"
        )

    return result


def _validate_manifest_files(
    root: Path,
    paths: Iterable[str],
) -> None:
    for relative in paths:
        candidate = root / relative

        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ManifestDiffAnalysisError(
                "Manifest path escapes repository"
            ) from exc

        if candidate.is_symlink():
            raise ManifestDiffAnalysisError(
                f"Manifest must not be a symlink: {relative}"
            )


def _redact(value: str) -> str:
    result = value

    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            result = pattern.sub(
                lambda match: (
                    f"{match.group(1)}"
                    f"{match.group(2)}"
                    f"{match.group(3)}"
                    "[REDACTED]"
                ),
                result,
            )
        else:
            result = pattern.sub(
                "[REDACTED]",
                result,
            )

    return result


def _manager_for_manifest(
    path: str,
) -> str | None:
    if path in SUPPORTED_MANIFESTS:
        return SUPPORTED_MANIFESTS[path]

    return SUPPORTED_MANIFESTS.get(
        Path(path).name
    )


def _parse_dependency_line(
    line: str,
    manager: str,
) -> tuple[str, str] | None:
    clean = line.strip()

    if not clean:
        return None

    match = _JSON_DEP_PATTERN.search(clean)

    if match and manager in {
        "npm",
        "pnpm",
        "yarn",
        "composer",
    }:
        return (
            match.group("name"),
            match.group("version"),
        )

    match = _PYTHON_DEP_PATTERN.search(clean)

    if match:
        return (
            match.group("name"),
            match.group("operator")
            + match.group("version"),
        )

    return None


def _is_dependency_context(
    line: str,
    manager: str,
) -> bool:
    lower = line.lower()

    if manager in {
        "npm",
        "pnpm",
        "yarn",
        "composer",
    }:
        return (
            "dependencies" in lower
            or "devdependencies" in lower
            or "optionaldependencies" in lower
            or "peerdependencies" in lower
            or bool(_JSON_DEP_PATTERN.search(line))
        )

    if manager in {
        "python",
        "pip",
        "pipenv",
        "poetry",
    }:
        return (
            "dependencies" in lower
            or "requires" in lower
            or bool(_PYTHON_DEP_PATTERN.search(line))
        )

    return True


@dataclass(frozen=True)
class ManifestDependencyChange:
    name: str
    old_version: str | None
    new_version: str | None
    change_type: str
    line_number: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise ManifestDiffAnalysisError(
                "Dependency name must be a string"
            )

        if not self.name.strip():
            raise ManifestDiffAnalysisError(
                "Dependency name must not be empty"
            )

        if self.old_version is not None and not isinstance(
            self.old_version,
            str,
        ):
            raise ManifestDiffAnalysisError(
                "old_version must be a string or None"
            )

        if self.new_version is not None and not isinstance(
            self.new_version,
            str,
        ):
            raise ManifestDiffAnalysisError(
                "new_version must be a string or None"
            )

        if self.change_type not in {
            "added",
            "removed",
            "updated",
        }:
            raise ManifestDiffAnalysisError(
                "Invalid dependency change type"
            )

        if type(self.line_number) is not int:
            raise ManifestDiffAnalysisError(
                "line_number must be an integer"
            )

        if self.line_number < 1:
            raise ManifestDiffAnalysisError(
                "line_number must be positive"
            )

        if self.change_type == "added":
            if self.old_version is not None:
                raise ManifestDiffAnalysisError(
                    "Added dependency cannot have old_version"
                )
            if self.new_version is None:
                raise ManifestDiffAnalysisError(
                    "Added dependency requires new_version"
                )

        if self.change_type == "removed":
            if self.old_version is None:
                raise ManifestDiffAnalysisError(
                    "Removed dependency requires old_version"
                )
            if self.new_version is not None:
                raise ManifestDiffAnalysisError(
                    "Removed dependency cannot have new_version"
                )

        if self.change_type == "updated":
            if self.old_version is None:
                raise ManifestDiffAnalysisError(
                    "Updated dependency requires old_version"
                )
            if self.new_version is None:
                raise ManifestDiffAnalysisError(
                    "Updated dependency requires new_version"
                )

    def to_dict(self) -> dict[str, object]:
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
    manager: str | None
    dependency_changes: tuple[
        ManifestDependencyChange,
        ...
    ]
    changed_lines: tuple[str, ...] = ()
    supported: bool = True

    def __post_init__(self) -> None:
        normalized = _normalize_relative_path(
            self.path
        )

        if normalized != self.path:
            raise ManifestDiffAnalysisError(
                "Manifest path is not normalized"
            )

        if self.manager is not None and not isinstance(
            self.manager,
            str,
        ):
            raise ManifestDiffAnalysisError(
                "manager must be a string or None"
            )

        if not isinstance(
            self.dependency_changes,
            tuple,
        ):
            raise ManifestDiffAnalysisError(
                "dependency_changes must be a tuple"
            )

        if len(self.dependency_changes) > MAX_ITEMS:
            raise ManifestDiffAnalysisError(
                "Too many dependency changes"
            )

        if not isinstance(
            self.changed_lines,
            tuple,
        ):
            raise ManifestDiffAnalysisError(
                "changed_lines must be a tuple"
            )

        if len(self.changed_lines) > MAX_ITEMS:
            raise ManifestDiffAnalysisError(
                "Too many changed lines"
            )

        if type(self.supported) is not bool:
            raise ManifestDiffAnalysisError(
                "supported must be boolean"
            )

        for item in self.dependency_changes:
            if not isinstance(
                item,
                ManifestDependencyChange,
            ):
                raise ManifestDiffAnalysisError(
                    "Invalid dependency change"
                )

        for line in self.changed_lines:
            if not isinstance(line, str):
                raise ManifestDiffAnalysisError(
                    "changed_lines must contain strings"
                )

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "manager": self.manager,
            "supported": self.supported,
            "dependency_changes": [
                item.to_dict()
                for item in self.dependency_changes
            ],
            "changed_lines": list(
                self.changed_lines
            ),
        }


@dataclass(frozen=True)
class ManifestDiffAnalysisResult:
    repository_root: str
    manifests: tuple[ManifestDiff, ...]
    unrelated_changes: tuple[str, ...]
    redacted_diff: str
    safe: bool = True

    def __post_init__(self) -> None:
        # repository_root is an absolute filesystem path.
        # It must NOT be validated as a relative manifest path.
        if not isinstance(
            self.repository_root,
            str,
        ):
            raise ManifestDiffAnalysisError(
                "repository_root must be a string"
            )

        if not self.repository_root.strip():
            raise ManifestDiffAnalysisError(
                "repository_root must not be empty"
            )

        if len(self.repository_root) > MAX_PATH_LENGTH:
            raise ManifestDiffAnalysisError(
                "repository_root is too long"
            )

        if _NULL in self.repository_root:
            raise ManifestDiffAnalysisError(
                "repository_root contains NULL"
            )

        root = Path(self.repository_root)

        if not root.is_absolute():
            raise ManifestDiffAnalysisError(
                "repository_root must be absolute"
            )

        if not isinstance(self.manifests, tuple):
            raise ManifestDiffAnalysisError(
                "manifests must be a tuple"
            )

        if not isinstance(
            self.unrelated_changes,
            tuple,
        ):
            raise ManifestDiffAnalysisError(
                "unrelated_changes must be a tuple"
            )

        if not isinstance(
            self.redacted_diff,
            str,
        ):
            raise ManifestDiffAnalysisError(
                "redacted_diff must be a string"
            )

        if len(self.redacted_diff) > MAX_DIFF_LENGTH:
            raise ManifestDiffAnalysisError(
                "redacted_diff is too long"
            )

        if type(self.safe) is not bool:
            raise ManifestDiffAnalysisError(
                "safe must be boolean"
            )

        for item in self.manifests:
            if not isinstance(
                item,
                ManifestDiff,
            ):
                raise ManifestDiffAnalysisError(
                    "Invalid manifest result"
                )

        for path in self.unrelated_changes:
            _normalize_relative_path(path)

    def to_dict(self) -> dict[str, object]:
        return {
            "repository_root": self.repository_root,
            "manifests": [
                item.to_dict()
                for item in self.manifests
            ],
            "unrelated_changes": list(
                self.unrelated_changes
            ),
            "redacted_diff": self.redacted_diff,
            "safe": self.safe,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


def _extract_blocks(
    diff_text: str,
) -> list[tuple[str, list[str]]]:
    blocks: list[
        tuple[str, list[str]]
    ] = []

    current_path: str | None = None
    current_lines: list[str] = []

    for line in diff_text.splitlines():
        match = _DIFF_FILE_PATTERN.match(line)

        if match:
            if current_path is not None:
                blocks.append(
                    (
                        current_path,
                        current_lines,
                    )
                )

            current_path = _normalize_relative_path(
                match.group("b")
            )
            current_lines = [line]
            continue

        if current_path is not None:
            current_lines.append(line)

    if current_path is not None:
        blocks.append(
            (
                current_path,
                current_lines,
            )
        )

    if len(blocks) > MAX_ITEMS:
        raise ManifestDiffAnalysisError(
            "Too many diff files"
        )

    return blocks


def _start_line(
    lines: Iterable[str],
) -> int:
    for line in lines:
        match = _HUNK_PATTERN.match(line)
        if match:
            return int(match.group("new"))

    return 1


def _dependency_changes(
    lines: Iterable[str],
    manager: str,
) -> tuple[ManifestDependencyChange, ...]:
    removed: dict[
        str,
        tuple[str, int],
    ] = {}

    added: dict[
        str,
        tuple[str, int],
    ] = {}

    current_line = _start_line(lines)

    for raw in lines:
        if raw.startswith("@@"):
            match = _HUNK_PATTERN.match(raw)
            if match:
                current_line = int(
                    match.group("new")
                )
            continue

        if raw.startswith("+++ ") or raw.startswith("--- "):
            continue

        prefix = raw[:1]
        content = (
            raw[1:]
            if prefix in {"+", "-"}
            else raw
        )

        parsed = _parse_dependency_line(
            content,
            manager,
        )

        if parsed is None:
            if prefix == "+":
                current_line += 1
            continue

        name, version = parsed

        if not _is_dependency_context(
            content,
            manager,
        ):
            if prefix == "+":
                current_line += 1
            continue

        if prefix == "-":
            removed[name] = (
                version,
                current_line,
            )

        elif prefix == "+":
            added[name] = (
                version,
                current_line,
            )

        if prefix == "+":
            current_line += 1

    changes: list[
        ManifestDependencyChange
    ] = []

    for name in sorted(
        set(removed) | set(added)
    ):
        old = removed.get(name)
        new = added.get(name)

        if old is not None and new is not None:
            changes.append(
                ManifestDependencyChange(
                    name=name,
                    old_version=old[0],
                    new_version=new[0],
                    change_type="updated",
                    line_number=new[1],
                )
            )

        elif new is not None:
            changes.append(
                ManifestDependencyChange(
                    name=name,
                    old_version=None,
                    new_version=new[0],
                    change_type="added",
                    line_number=new[1],
                )
            )

        elif old is not None:
            changes.append(
                ManifestDependencyChange(
                    name=name,
                    old_version=old[0],
                    new_version=None,
                    change_type="removed",
                    line_number=old[1],
                )
            )

    return tuple(changes)


def analyze_manifest_diff(
    repository_root: str | Path,
    diff_text: str,
    manifests: Iterable[str],
) -> ManifestDiffAnalysisResult:
    root = _validate_repository_root(
        repository_root
    )

    diff_text = _validate_text(
        diff_text,
        "Diff",
        MAX_DIFF_LENGTH,
    )

    manifest_paths = _normalize_manifest_paths(
        manifests
    )

    _validate_manifest_files(
        root,
        manifest_paths,
    )

    blocks = _extract_blocks(
        diff_text
    )

    manifest_set = set(manifest_paths)

    results: list[ManifestDiff] = []
    unrelated: list[str] = []

    for path, lines in blocks:
        if path not in manifest_set:
            unrelated.append(path)
            continue

        manager = _manager_for_manifest(path)
        supported = manager is not None

        changes = (
            _dependency_changes(
                lines,
                manager,
            )
            if manager is not None
            else ()
        )

        changed_lines = tuple(
            _redact(line)
            for line in lines
            if (
                line.startswith("+")
                or line.startswith("-")
            )
            and not line.startswith(
                ("+++", "---")
            )
        )

        results.append(
            ManifestDiff(
                path=path,
                manager=manager,
                dependency_changes=changes,
                changed_lines=changed_lines,
                supported=supported,
            )
        )

    existing = {
        item.path
        for item in results
    }

    for path in manifest_paths:
        if path not in existing:
            results.append(
                ManifestDiff(
                    path=path,
                    manager=_manager_for_manifest(
                        path
                    ),
                    dependency_changes=(),
                    changed_lines=(),
                    supported=(
                        _manager_for_manifest(
                            path
                        )
                        is not None
                    ),
                )
            )

    order = {
        path: index
        for index, path in enumerate(
            manifest_paths
        )
    }

    results.sort(
        key=lambda item: order[item.path]
    )

    return ManifestDiffAnalysisResult(
        repository_root=str(root),
        manifests=tuple(results),
        unrelated_changes=tuple(
            dict.fromkeys(unrelated)
        ),
        redacted_diff=_redact(diff_text),
        safe=True,
    )


def validate_manifest_diff_analysis(
    result: ManifestDiffAnalysisResult,
) -> bool:
    if not isinstance(
        result,
        ManifestDiffAnalysisResult,
    ):
        return False

    try:
        root = Path(
            result.repository_root
        )

        if not root.is_absolute():
            return False

        if not root.exists() or not root.is_dir():
            return False

        ManifestDiffAnalysisResult(
            repository_root=result.repository_root,
            manifests=result.manifests,
            unrelated_changes=result.unrelated_changes,
            redacted_diff=result.redacted_diff,
            safe=result.safe,
        )

        return True

    except (
        ManifestDiffAnalysisError,
        OSError,
        RuntimeError,
    ):
        return False


def analyze_manifest_diffs(
    repository_root: str | Path,
    diff_text: str,
    manifests: Iterable[str],
) -> ManifestDiffAnalysisResult:
    return analyze_manifest_diff(
        repository_root,
        diff_text,
        manifests,
    )


def validate_manifest_diff(
    result: ManifestDiffAnalysisResult,
) -> bool:
    return validate_manifest_diff_analysis(
        result
    )


__all__ = [
    "MAX_PATH_LENGTH",
    "MAX_DIFF_LENGTH",
    "MAX_ITEMS",
    "SUPPORTED_MANIFESTS",
    "ManifestDiffAnalysisError",
    "ManifestDependencyChange",
    "ManifestDiff",
    "ManifestDiffAnalysisResult",
    "analyze_manifest_diff",
    "analyze_manifest_diffs",
    "validate_manifest_diff_analysis",
    "validate_manifest_diff",
]
