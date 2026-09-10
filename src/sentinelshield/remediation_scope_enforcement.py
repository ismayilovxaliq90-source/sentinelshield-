from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence
import json
import subprocess


class RemediationScopeError(Exception):
    """Raised when remediation scope validation cannot be completed."""


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
    approved_scope: tuple[str, ...] = ()
    accepted_changes: tuple[ScopeChange, ...] = ()
    out_of_scope_changes: tuple[ScopeChange, ...] = ()
    added_files: tuple[str, ...] = ()
    modified_files: tuple[str, ...] = ()
    deleted_files: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def passed(self) -> bool:
        return self.valid and self.in_scope

    def to_dict(self) -> dict:
        return {
            "repository_root": self.repository_root,
            "valid": self.valid,
            "in_scope": self.in_scope,
            "passed": self.passed,
            "approved_scope": list(self.approved_scope),
            "accepted_changes": [
                item.to_dict() for item in self.accepted_changes
            ],
            "out_of_scope_changes": [
                item.to_dict() for item in self.out_of_scope_changes
            ],
            "added_files": list(self.added_files),
            "modified_files": list(self.modified_files),
            "deleted_files": list(self.deleted_files),
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _validate_repository_root(repository_root: Path) -> Path:
    try:
        root = Path(repository_root).expanduser().resolve()
    except (OSError, RuntimeError, TypeError) as exc:
        raise RemediationScopeError(
            "Unable to resolve repository root"
        ) from exc

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


def _normalize_relative_path(
    repository_root: Path,
    value: str | Path,
) -> str:
    if not isinstance(value, (str, Path)):
        raise RemediationScopeError(
            "Scope path must be a string or Path"
        )

    raw = str(value).strip()

    if not raw:
        raise RemediationScopeError(
            "Scope path cannot be empty"
        )

    if "\x00" in raw:
        raise RemediationScopeError(
            "NULL character is not allowed in scope path"
        )

    candidate = Path(raw)

    if candidate.is_absolute():
        resolved = candidate.expanduser().resolve()
    else:
        resolved = (repository_root / candidate).resolve()

    try:
        relative = resolved.relative_to(repository_root)
    except ValueError as exc:
        raise RemediationScopeError(
            f"Scope path is outside repository: {value}"
        ) from exc

    if relative == Path("."):
        raise RemediationScopeError(
            "Repository root itself cannot be an approved remediation path"
        )

    return relative.as_posix()


def normalize_approved_scope(
    repository_root: Path,
    approved_paths: Iterable[str | Path],
) -> tuple[str, ...]:
    root = _validate_repository_root(repository_root)

    if isinstance(approved_paths, (str, Path)):
        raise RemediationScopeError(
            "Approved scope must be an iterable of paths, not one path"
        )

    normalized = {
        _normalize_relative_path(root, item)
        for item in approved_paths
    }

    if not normalized:
        raise RemediationScopeError(
            "Approved remediation scope cannot be empty"
        )

    return tuple(sorted(normalized))


def _is_within_scope(path: str, scope_path: str) -> bool:
    if path == scope_path:
        return True

    return path.startswith(scope_path.rstrip("/") + "/")


def _run_git_status(repository_root: Path) -> list[ScopeChange]:
    try:
        completed = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=repository_root,
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
            completed.stderr.strip() or "Git status failed"
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
        path_text = line[3:]

        if "->" in path_text:
            old_path, new_path = [
                item.strip()
                for item in path_text.split("->", 1)
            ]

            changes.append(
                ScopeChange(path=old_path, status="D")
            )
            changes.append(
                ScopeChange(path=new_path, status="A")
            )
            continue

        if status == "??":
            normalized_status = "A"
        elif "D" in status:
            normalized_status = "D"
        elif "A" in status:
            normalized_status = "A"
        elif "R" in status:
            normalized_status = "R"
        elif "C" in status:
            normalized_status = "C"
        else:
            normalized_status = "M"

        changes.append(
            ScopeChange(
                path=Path(path_text).as_posix(),
                status=normalized_status,
            )
        )

    return sorted(changes, key=lambda item: item.path)


def _validate_change_paths(
    repository_root: Path,
    changes: Sequence[ScopeChange],
) -> None:
    for change in changes:
        candidate = (repository_root / change.path).resolve()

        try:
            candidate.relative_to(repository_root)
        except ValueError as exc:
            raise RemediationScopeError(
                f"Git change is outside repository: {change.path}"
            ) from exc


def enforce_remediation_scope(
    repository_root: Path,
    approved_paths: Iterable[str | Path],
) -> RemediationScopeResult:
    root = _validate_repository_root(repository_root)

    scope = normalize_approved_scope(
        root,
        approved_paths,
    )

    changes = _run_git_status(root)
    _validate_change_paths(root, changes)

    accepted: list[ScopeChange] = []
    out_of_scope: list[ScopeChange] = []

    for change in changes:
        if any(
            _is_within_scope(change.path, scope_path)
            for scope_path in scope
        ):
            accepted.append(change)
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
        approved_scope=scope,
        accepted_changes=tuple(accepted),
        out_of_scope_changes=tuple(out_of_scope),
        added_files=added,
        modified_files=modified,
        deleted_files=deleted,
        reason=(
            None
            if passed
            else "REMEDIATION_SCOPE_VIOLATION"
        ),
    )


def validate_remediation_scope_result(
    result: RemediationScopeResult,
) -> bool:
    if not isinstance(result, RemediationScopeResult):
        raise RemediationScopeError(
            "Invalid remediation scope result"
        )

    if not result.valid:
        return False

    if result.out_of_scope_changes:
        return False

    return result.in_scope


def verify_remediation_scope(
    repository_root: Path,
    approved_paths: Iterable[str | Path],
) -> RemediationScopeResult:
    result = enforce_remediation_scope(
        repository_root=repository_root,
        approved_paths=approved_paths,
    )

    if not validate_remediation_scope_result(result):
        return result

    return result
