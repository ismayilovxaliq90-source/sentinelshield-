from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence
import hashlib
import json
import subprocess


class UnexpectedFileChangeError(Exception):
    """Raised when unexpected repository file changes are detected."""


@dataclass(frozen=True)
class FileChange:
    path: str
    status: str
    before_sha256: str | None = None
    after_sha256: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "status": self.status,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
        }


@dataclass(frozen=True)
class UnexpectedFileChangeResult:
    repository_root: str
    clean: bool
    valid: bool
    expected_changes: tuple[FileChange, ...] = ()
    unexpected_changes: tuple[FileChange, ...] = ()
    added_files: tuple[str, ...] = ()
    modified_files: tuple[str, ...] = ()
    deleted_files: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def passed(self) -> bool:
        return self.valid and self.clean and not self.unexpected_changes

    def to_dict(self) -> dict:
        return {
            "repository_root": self.repository_root,
            "clean": self.clean,
            "valid": self.valid,
            "passed": self.passed,
            "expected_changes": [
                item.to_dict() for item in self.expected_changes
            ],
            "unexpected_changes": [
                item.to_dict() for item in self.unexpected_changes
            ],
            "added_files": list(self.added_files),
            "modified_files": list(self.modified_files),
            "deleted_files": list(self.deleted_files),
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _validate_root(repository_root: Path) -> Path:
    root = Path(repository_root).expanduser().resolve()

    if not root.exists():
        raise UnexpectedFileChangeError(
            f"Repository root does not exist: {root}"
        )

    if not root.is_dir():
        raise UnexpectedFileChangeError(
            f"Repository root is not a directory: {root}"
        )

    git_dir = root / ".git"
    if not git_dir.exists():
        raise UnexpectedFileChangeError(
            f"Not a Git repository: {root}"
        )

    return root


def _safe_relative(root: Path, path: Path) -> str:
    resolved = path.resolve()

    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise UnexpectedFileChangeError(
            f"Path outside repository: {path}"
        ) from exc

    if relative == Path("."):
        raise UnexpectedFileChangeError(
            "Repository root cannot be a changed file"
        )

    return relative.as_posix()


def _run_git(root: Path, args: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UnexpectedFileChangeError(
            f"Unable to execute git: {exc}"
        ) from exc

    if completed.returncode != 0:
        raise UnexpectedFileChangeError(
            completed.stderr.strip() or
            f"git command failed: {args}"
        )

    return completed.stdout


def _sha256(path: Path) -> str | None:
    if not path.exists():
        return None

    if path.is_symlink():
        raise UnexpectedFileChangeError(
            f"Symlink is not allowed: {path}"
        )

    if not path.is_file():
        raise UnexpectedFileChangeError(
            f"Changed path is not a regular file: {path}"
        )

    digest = hashlib.sha256()

    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise UnexpectedFileChangeError(
            f"Unable to fingerprint file: {path}"
        ) from exc

    return digest.hexdigest()


def collect_git_changes(repository_root: Path) -> tuple[FileChange, ...]:
    root = _validate_root(repository_root)

    output = _run_git(
        root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
    )

    changes: list[FileChange] = []

    for raw_line in output.splitlines():
        if not raw_line:
            continue

        if len(raw_line) < 4:
            raise UnexpectedFileChangeError(
                f"Malformed git status entry: {raw_line!r}"
            )

        status = raw_line[:2]
        raw_path = raw_line[3:]

        if "->" in raw_path:
            old_path, new_path = [
                part.strip() for part in raw_path.split("->", 1)
            ]

            for path_text, change_status in (
                (old_path, "D"),
                (new_path, "A"),
            ):
                candidate = (root / path_text).resolve()
                relative = _safe_relative(root, candidate)

                changes.append(
                    FileChange(
                        path=relative,
                        status=change_status,
                        after_sha256=_sha256(candidate),
                    )
                )
            continue

        if raw_path.startswith('"') and raw_path.endswith('"'):
            raw_path = raw_path[1:-1]

        candidate = (root / raw_path).resolve()
        relative = _safe_relative(root, candidate)

        index_status = status[0]
        worktree_status = status[1]

        if index_status == "?" and worktree_status == "?":
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
            FileChange(
                path=relative,
                status=normalized_status,
                after_sha256=_sha256(candidate),
            )
        )

    return tuple(sorted(changes, key=lambda item: item.path))


def _normalize_expected(
    expected_changes: Iterable[str | FileChange] | None,
) -> frozenset[str]:
    if expected_changes is None:
        return frozenset()

    normalized: set[str] = set()

    for item in expected_changes:
        path = item.path if isinstance(item, FileChange) else str(item)

        if not path.strip():
            raise UnexpectedFileChangeError(
                "Expected change path cannot be empty"
            )

        normalized.add(Path(path).as_posix().lstrip("./"))

    return frozenset(normalized)


def detect_unexpected_file_changes(
    repository_root: Path,
    expected_changes: Iterable[str | FileChange] | None = None,
) -> UnexpectedFileChangeResult:
    root = _validate_root(repository_root)
    expected = _normalize_expected(expected_changes)

    changes = collect_git_changes(root)

    expected_result: list[FileChange] = []
    unexpected: list[FileChange] = []

    for change in changes:
        if change.path in expected:
            expected_result.append(change)
        else:
            unexpected.append(change)

    added = tuple(
        sorted(item.path for item in changes if item.status == "A")
    )
    modified = tuple(
        sorted(item.path for item in changes if item.status == "M")
    )
    deleted = tuple(
        sorted(item.path for item in changes if item.status == "D")
    )

    return UnexpectedFileChangeResult(
        repository_root=str(root),
        clean=not bool(changes),
        valid=True,
        expected_changes=tuple(expected_result),
        unexpected_changes=tuple(unexpected),
        added_files=added,
        modified_files=modified,
        deleted_files=deleted,
        reason=(
            None
            if not unexpected
            else "UNEXPECTED_FILE_CHANGE"
        ),
    )


def validate_unexpected_file_change_result(
    result: UnexpectedFileChangeResult,
) -> bool:
    if not isinstance(result, UnexpectedFileChangeResult):
        raise UnexpectedFileChangeError(
            "Invalid result type"
        )

    if not result.valid:
        return False

    if result.unexpected_changes:
        return False

    return result.clean


def verify_repository_file_changes(
    repository_root: Path,
    expected_changes: Iterable[str | FileChange] | None = None,
) -> UnexpectedFileChangeResult:
    result = detect_unexpected_file_changes(
        repository_root=repository_root,
        expected_changes=expected_changes,
    )

    if not result.valid:
        raise UnexpectedFileChangeError(
            result.reason or "FILE_CHANGE_VALIDATION_FAILED"
        )

    return result
