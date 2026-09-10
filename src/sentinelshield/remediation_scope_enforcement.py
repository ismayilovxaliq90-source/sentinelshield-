from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import json
import subprocess


class RemediationScopeError(Exception):
    """Raised when remediation scope validation cannot be performed safely."""


@dataclass(frozen=True)
class ScopeChange:
    path: str
    status: str

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "status": self.status,
        }


@dataclass(frozen=True)
class RemediationScopeResult:
    repository_root: str
    valid: bool
    in_scope: bool
    allowed_changes: tuple[ScopeChange, ...] = ()
    out_of_scope_changes: tuple[ScopeChange, ...] = ()
    added_files: tuple[str, ...] = ()
    modified_files: tuple[str, ...] = ()
    deleted_files: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def passed(self) -> bool:
        return (
            self.valid
            and self.in_scope
            and not self.out_of_scope_changes
        )

    def to_dict(self) -> dict:
        return {
            "repository_root": self.repository_root,
            "valid": self.valid,
            "in_scope": self.in_scope,
            "passed": self.passed,
            "allowed_changes": [
                item.to_dict() for item in self.allowed_changes
            ],
            "out_of_scope_changes": [
                item.to_dict()
                for item in self.out_of_scope_changes
            ],
            "added_files": list(self.added_files),
            "modified_files": list(self.modified_files),
            "deleted_files": list(self.deleted_files),
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _validate_repository_root(repository_root: Path) -> Path:
    root = Path(repository_root).expanduser().resolve()

    if not root.exists():
        raise RemediationScopeError(
            f"Repository root does not exist: {root}"
        )

    if not root.is_dir():
        raise RemediationScopeError(
            f"Repository root is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise RemediationScopeError(
            f"Not a Git repository: {root}"
        )

    return root


def _normalize_scope_path(root: Path, value: str | Path) -> str:
    if not isinstance(value, (str, Path)):
        raise RemediationScopeError(
            f"Unsupported scope path type: {type(value).__name__}"
        )

    raw = str(value)

    if not raw.strip():
        raise RemediationScopeError(
            "Scope path cannot be empty"
        )

    candidate = Path(raw)

    if candidate.is_absolute():
        raise RemediationScopeError(
            f"Absolute scope path is not allowed: {raw}"
        )

    normalized = Path(raw)

    if any(part == ".." for part in normalized.parts):
        raise RemediationScopeError(
            f"Parent traversal is not allowed: {raw}"
        )

    normalized_text = normalized.as_posix().lstrip("./")

    if not normalized_text or normalized_text == ".":
        raise RemediationScopeError(
            "Repository root cannot be used as a scope path"
        )

    resolved = (root / normalized).resolve()

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RemediationScopeError(
            f"Scope path escapes repository: {raw}"
        ) from exc

    if resolved.is_symlink():
        raise RemediationScopeError(
            f"Symlink scope path is not allowed: {raw}"
        )

    return normalized_text


def normalize_allowed_scope(
    repository_root: Path,
    allowed_paths: Iterable[str | Path],
) -> frozenset[str]:
    root = _validate_repository_root(repository_root)

    if allowed_paths is None:
        raise RemediationScopeError(
            "Allowed scope cannot be None"
        )

    normalized: set[str] = set()

    for value in allowed_paths:
        normalized.add(
            _normalize_scope_path(root, value)
        )

    return frozenset(normalized)


def _git_status(root: Path) -> list[ScopeChange]:
    try:
        completed = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RemediationScopeError(
            f"Unable to inspect Git status: {exc}"
        ) from exc

    if completed.returncode != 0:
        raise RemediationScopeError(
            completed.stderr.strip()
            or "Git status failed"
        )

    changes: list[ScopeChange] = []

    for line in completed.stdout.splitlines():
        if not line:
            continue

        if len(line) < 4:
            raise RemediationScopeError(
                f"Malformed Git status entry: {line!r}"
            )

        status = line[:2]
        raw_path = line[3:]

        if "->" in raw_path:
            old_path, new_path = (
                part.strip()
                for part in raw_path.split("->", 1)
            )

            changes.append(
                ScopeChange(
                    path=old_path.replace("\\", "/"),
                    status="D",
                )
            )
            changes.append(
                ScopeChange(
                    path=new_path.replace("\\", "/"),
                    status="A",
                )
            )
            continue

        if raw_path.startswith('"') and raw_path.endswith('"'):
            raw_path = raw_path[1:-1]

        if status == "??":
            normalized_status = "A"
        elif "D" in status:
            normalized_status = "D"
        elif "A" in status:
            normalized_status = "A"
        elif "R" in status:
            normalized_status = "R"
        else:
            normalized_status = "M"

        changes.append(
            ScopeChange(
                path=raw_path.replace("\\", "/"),
                status=normalized_status,
            )
        )

    return sorted(
        changes,
        key=lambda item: (item.path, item.status),
    )


def _path_in_scope(path: str, allowed_paths: frozenset[str]) -> bool:
    normalized = Path(path).as_posix().lstrip("./")

    for allowed in allowed_paths:
        if normalized == allowed:
            return True

        prefix = allowed.rstrip("/") + "/"

        if normalized.startswith(prefix):
            return True

    return False


def enforce_remediation_scope(
    repository_root: Path,
    allowed_paths: Iterable[str | Path],
) -> RemediationScopeResult:
    root = _validate_repository_root(repository_root)

    scope = normalize_allowed_scope(
        root,
        allowed_paths,
    )

    changes = _git_status(root)

    allowed: list[ScopeChange] = []
    out_of_scope: list[ScopeChange] = []

    for change in changes:
        path = Path(change.path)

        if path.is_absolute():
            out_of_scope.append(change)
            continue

        if any(part == ".." for part in path.parts):
            out_of_scope.append(change)
            continue

        if _path_in_scope(change.path, scope):
            allowed.append(change)
        else:
            out_of_scope.append(change)

    added = tuple(
        sorted(
            item.path
            for item in changes
            if item.status == "A"
        )
    )

    modified = tuple(
        sorted(
            item.path
            for item in changes
            if item.status == "M"
        )
    )

    deleted = tuple(
        sorted(
            item.path
            for item in changes
            if item.status == "D"
        )
    )

    passed = not out_of_scope

    return RemediationScopeResult(
        repository_root=str(root),
        valid=True,
        in_scope=passed,
        allowed_changes=tuple(allowed),
        out_of_scope_changes=tuple(out_of_scope),
        added_files=added,
        modified_files=modified,
        deleted_files=deleted,
        reason=None if passed else "REMEDIATION_OUT_OF_SCOPE",
    )


def validate_remediation_scope_result(
    result: RemediationScopeResult,
) -> bool:
    if not isinstance(result, RemediationScopeResult):
        raise RemediationScopeError(
            "Invalid remediation scope result"
        )

    return result.passed
