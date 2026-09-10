from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence
import json
import subprocess


class RemediationScopeError(Exception):
    """Raised when remediation scope validation fails."""


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
    approved_scope: tuple[str, ...]
    accepted_changes: tuple[ScopeChange, ...]
    out_of_scope_changes: tuple[ScopeChange, ...]
    added_files: tuple[str, ...]
    modified_files: tuple[str, ...]
    deleted_files: tuple[str, ...]
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
                item.to_dict()
                for item in self.out_of_scope_changes
            ],
            "added_files": list(self.added_files),
            "modified_files": list(self.modified_files),
            "deleted_files": list(self.deleted_files),
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


def _repository_root(repository_root: str | Path) -> Path:
    if not isinstance(repository_root, (str, Path)):
        raise RemediationScopeError(
            "Repository root must be a string or Path"
        )

    raw = str(repository_root).strip()

    if not raw:
        raise RemediationScopeError(
            "Repository root cannot be empty"
        )

    if "\x00" in raw:
        raise RemediationScopeError(
            "NULL character is not allowed"
        )

    try:
        root = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
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


def _normalize_scope_path(
    root: Path,
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

    try:
        if candidate.is_absolute():
            resolved = candidate.expanduser().resolve()
        else:
            resolved = (root / candidate).resolve()
    except (OSError, RuntimeError) as exc:
        raise RemediationScopeError(
            f"Unable to resolve scope path: {value}"
        ) from exc

    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise RemediationScopeError(
            f"Scope path is outside repository: {value}"
        ) from exc

    if relative == Path("."):
        raise RemediationScopeError(
            "Repository root cannot be remediation scope"
        )

    return relative.as_posix()


def normalize_approved_scope(
    repository_root: str | Path,
    approved_paths: Iterable[str | Path],
) -> tuple[str, ...]:
    root = _repository_root(repository_root)

    if isinstance(approved_paths, (str, Path)):
        raise RemediationScopeError(
            "Approved scope must be an iterable of paths"
        )

    try:
        items = list(approved_paths)
    except TypeError as exc:
        raise RemediationScopeError(
            "Approved scope must be iterable"
        ) from exc

    if not items:
        raise RemediationScopeError(
            "Approved remediation scope cannot be empty"
        )

    normalized = {
        _normalize_scope_path(root, item)
        for item in items
    }

    if not normalized:
        raise RemediationScopeError(
            "Approved remediation scope cannot be empty"
        )

    return tuple(sorted(normalized))


def _path_in_scope(
    changed_path: str,
    scope_path: str,
) -> bool:
    return (
        changed_path == scope_path
        or changed_path.startswith(
            scope_path.rstrip("/") + "/"
        )
    )


def _git_status(
    root: Path,
) -> tuple[ScopeChange, ...]:
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
        path_text = line[3:]

        if "->" in path_text:
            old_path, new_path = (
                part.strip()
                for part in path_text.split("->", 1)
            )

            changes.append(
                ScopeChange(
                    path=Path(old_path).as_posix(),
                    status="D",
                )
            )

            changes.append(
                ScopeChange(
                    path=Path(new_path).as_posix(),
                    status="A",
                )
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

    return tuple(
        sorted(
            changes,
            key=lambda item: item.path,
        )
    )


def _validate_change_paths(
    root: Path,
    changes: Sequence[ScopeChange],
) -> None:
    for change in changes:
        candidate = root / change.path

        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise RemediationScopeError(
                f"Git change is outside repository: {change.path}"
            ) from exc


def enforce_remediation_scope(
    repository_root: str | Path,
    approved_paths: Iterable[str | Path],
) -> RemediationScopeResult:
    root = _repository_root(repository_root)

    scope = normalize_approved_scope(
        root,
        approved_paths,
    )

    changes = _git_status(root)

    _validate_change_paths(
        root,
        changes,
    )

    accepted: list[ScopeChange] = []
    unexpected: list[ScopeChange] = []

    for change in changes:
        if any(
            _path_in_scope(change.path, scope_path)
            for scope_path in scope
        ):
            accepted.append(change)
        else:
            unexpected.append(change)

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

    in_scope = not unexpected

    return RemediationScopeResult(
        repository_root=str(root),
        valid=True,
        in_scope=in_scope,
        approved_scope=scope,
        accepted_changes=tuple(accepted),
        out_of_scope_changes=tuple(unexpected),
        added_files=added,
        modified_files=modified,
        deleted_files=deleted,
        reason=(
            None
            if in_scope
            else "REMEDIATION_SCOPE_VIOLATION"
        ),
    )


def validate_remediation_scope_result(
    result: RemediationScopeResult,
) -> bool:
    if not isinstance(
        result,
        RemediationScopeResult,
    ):
        raise RemediationScopeError(
            "Invalid remediation scope result"
        )

    return (
        result.valid
        and result.in_scope
        and not result.out_of_scope_changes
    )


def verify_remediation_scope(
    repository_root: str | Path,
    approved_paths: Iterable[str | Path],
) -> RemediationScopeResult:
    return enforce_remediation_scope(
        repository_root,
        approved_paths,
    )
