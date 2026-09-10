from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


class GitDiffCollectionError(ValueError):
    """Raised when Git diff collection cannot be performed safely."""


_MAX_PATH_LENGTH = 4096
_MAX_DIFF_LENGTH = 2_000_000
_MAX_OUTPUT_LENGTH = 2_000_000

_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)(token|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
)


def _redact(text: str) -> str:
    value = text
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(
            lambda match: f"{match.group(0).split(':', 1)[0].split('=', 1)[0]}=<REDACTED>",
            value,
        )
    return value


def _normalize_path(value: str) -> str:
    if not isinstance(value, str):
        raise GitDiffCollectionError("Path must be a string")

    value = value.strip()

    if not value:
        raise GitDiffCollectionError("Path must not be empty")

    if len(value) > _MAX_PATH_LENGTH:
        raise GitDiffCollectionError("Path is too long")

    if "\x00" in value:
        raise GitDiffCollectionError("NULL character is not allowed")

    return value


def _normalize_reference(value: str) -> str:
    if not isinstance(value, str):
        raise GitDiffCollectionError("Git reference must be a string")

    value = value.strip()

    if not value:
        raise GitDiffCollectionError("Git reference must not be empty")

    if len(value) > 512:
        raise GitDiffCollectionError("Git reference is too long")

    if "\x00" in value:
        raise GitDiffCollectionError("NULL character is not allowed")

    # Git references must never be interpreted as command-line options.
    if value.startswith("-"):
        raise GitDiffCollectionError("Git reference cannot start with '-'")

    return value


def _validate_repository(root: Path) -> Path:
    try:
        resolved = root.expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise GitDiffCollectionError("Unable to resolve repository path") from exc

    if not resolved.exists() or not resolved.is_dir():
        raise GitDiffCollectionError("Repository root is not a directory")

    git_dir = resolved / ".git"

    if not git_dir.exists():
        raise GitDiffCollectionError("Repository does not contain .git")

    if git_dir.is_symlink():
        raise GitDiffCollectionError(".git must not be a symlink")

    return resolved


def _run_git(
    root: Path,
    arguments: list[str],
    *,
    timeout: float,
) -> tuple[int, str, str]:
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise GitDiffCollectionError("Timeout must be numeric")

    if timeout <= 0 or timeout > 120:
        raise GitDiffCollectionError("Timeout is outside the allowed range")

    command = ["git", "-C", str(root), "--no-pager", *arguments]

    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            timeout=float(timeout),
        )
    except subprocess.TimeoutExpired as exc:
        raise GitDiffCollectionError("Git command timed out") from exc
    except OSError as exc:
        raise GitDiffCollectionError("Unable to execute Git") from exc

    stdout = completed.stdout
    stderr = completed.stderr

    if len(stdout) > _MAX_OUTPUT_LENGTH:
        raise GitDiffCollectionError("Git stdout exceeds safety limit")

    if len(stderr) > _MAX_OUTPUT_LENGTH:
        raise GitDiffCollectionError("Git stderr exceeds safety limit")

    return completed.returncode, stdout, stderr


@dataclass(frozen=True)
class GitDiffFile:
    path: str
    status: str
    old_path: str | None = None
    additions: int = 0
    deletions: int = 0
    binary: bool = False

    def __post_init__(self) -> None:
        normalized = _normalize_path(self.path)

        if self.status not in {
            "added",
            "modified",
            "deleted",
            "renamed",
            "copied",
            "untracked",
            "unknown",
        }:
            raise GitDiffCollectionError("Invalid file status")

        if self.old_path is not None:
            _normalize_path(self.old_path)

        if type(self.additions) is not int or self.additions < 0:
            raise GitDiffCollectionError("Invalid additions count")

        if type(self.deletions) is not int or self.deletions < 0:
            raise GitDiffCollectionError("Invalid deletions count")

        object.__setattr__(self, "path", normalized)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "status": self.status,
            "old_path": self.old_path,
            "additions": self.additions,
            "deletions": self.deletions,
            "binary": self.binary,
        }


@dataclass(frozen=True)
class GitDiffCollectionResult:
    repository_root: str
    baseline: str | None
    files: tuple[GitDiffFile, ...] = field(default_factory=tuple)
    additions: int = 0
    deletions: int = 0
    changed_files: int = 0
    raw_diff: str = ""
    status_output: str = ""

    def __post_init__(self) -> None:
        root = _normalize_path(self.repository_root)

        if self.baseline is not None:
            _normalize_reference(self.baseline)

        if type(self.additions) is not int or self.additions < 0:
            raise GitDiffCollectionError("Invalid total additions")

        if type(self.deletions) is not int or self.deletions < 0:
            raise GitDiffCollectionError("Invalid total deletions")

        if type(self.changed_files) is not int or self.changed_files < 0:
            raise GitDiffCollectionError("Invalid changed file count")

        if len(self.raw_diff) > _MAX_DIFF_LENGTH:
            raise GitDiffCollectionError("Raw diff exceeds safety limit")

        if self.changed_files != len(self.files):
            raise GitDiffCollectionError(
                "Changed file count does not match file collection"
            )

        if self.additions != sum(item.additions for item in self.files):
            raise GitDiffCollectionError(
                "Addition count does not match file collection"
            )

        if self.deletions != sum(item.deletions for item in self.files):
            raise GitDiffCollectionError(
                "Deletion count does not match file collection"
            )

        object.__setattr__(self, "repository_root", root)

    @property
    def has_changes(self) -> bool:
        return bool(self.files)

    def to_dict(self) -> dict:
        return {
            "repository_root": self.repository_root,
            "baseline": self.baseline,
            "files": [item.to_dict() for item in self.files],
            "additions": self.additions,
            "deletions": self.deletions,
            "changed_files": self.changed_files,
            "raw_diff": _redact(self.raw_diff),
            "status_output": _redact(self.status_output),
            "has_changes": self.has_changes,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def _status_name(code: str) -> str:
    mapping = {
        "A": "added",
        "M": "modified",
        "D": "deleted",
        "R": "renamed",
        "C": "copied",
        "?": "untracked",
        "!": "ignored",
    }
    return mapping.get(code, "unknown")


def _parse_name_status(output: str) -> list[tuple[str, str, str | None]]:
    results: list[tuple[str, str, str | None]] = []

    for line in output.splitlines():
        if not line:
            continue

        parts = line.split("\t")

        if not parts:
            continue

        code = parts[0][:1]

        if code in {"R", "C"} and len(parts) >= 3:
            results.append(
                (
                    _status_name(code),
                    parts[2],
                    parts[1],
                )
            )
        elif len(parts) >= 2:
            results.append(
                (
                    _status_name(code),
                    parts[-1],
                    None,
                )
            )

    return results


def _parse_numstat(output: str) -> dict[str, tuple[int, int, bool]]:
    result: dict[str, tuple[int, int, bool]] = {}

    for line in output.splitlines():
        if not line:
            continue

        parts = line.split("\t")

        if len(parts) < 3:
            continue

        additions_raw, deletions_raw, path = parts[0], parts[1], parts[-1]

        if additions_raw == "-" or deletions_raw == "-":
            result[path] = (0, 0, True)
            continue

        try:
            additions = int(additions_raw)
            deletions = int(deletions_raw)
        except ValueError:
            continue

        result[path] = (additions, deletions, False)

    return result


def collect_git_diff(
    repository_root: str | Path,
    baseline: str | None = None,
    *,
    include_untracked: bool = True,
    timeout: float = 30.0,
) -> GitDiffCollectionResult:
    if not isinstance(repository_root, (str, Path)):
        raise GitDiffCollectionError("Repository root must be a path")

    root = _validate_repository(Path(repository_root))

    if type(include_untracked) is not bool:
        raise GitDiffCollectionError("include_untracked must be boolean")

    normalized_baseline = (
        _normalize_reference(baseline) if baseline is not None else None
    )

    # Verify Git repository state first.
    code, _, stderr = _run_git(
        root,
        ["rev-parse", "--show-toplevel"],
        timeout=timeout,
    )

    if code != 0:
        raise GitDiffCollectionError(
            f"Unable to inspect Git repository: {_redact(stderr.strip())}"
        )

    diff_arguments = ["diff", "--no-ext-diff", "--unified=3"]

    if normalized_baseline is not None:
        diff_arguments.append(normalized_baseline)

    code, raw_diff, stderr = _run_git(
        root,
        diff_arguments,
        timeout=timeout,
    )

    if code != 0:
        raise GitDiffCollectionError(
            f"Git diff failed: {_redact(stderr.strip())}"
        )

    if len(raw_diff) > _MAX_DIFF_LENGTH:
        raise GitDiffCollectionError("Git diff exceeds safety limit")

    status_arguments = [
        "status",
        "--short",
        "--untracked-files=all" if include_untracked else "--untracked-files=no",
    ]

    code, status_output, stderr = _run_git(
        root,
        status_arguments,
        timeout=timeout,
    )

    if code != 0:
        raise GitDiffCollectionError(
            f"Git status failed: {_redact(stderr.strip())}"
        )

    name_status_arguments = [
        "diff",
        "--no-ext-diff",
        "--name-status",
    ]

    if normalized_baseline is not None:
        name_status_arguments.append(normalized_baseline)

    code, name_status, stderr = _run_git(
        root,
        name_status_arguments,
        timeout=timeout,
    )

    if code != 0:
        raise GitDiffCollectionError(
            f"Git name-status failed: {_redact(stderr.strip())}"
        )

    numstat_arguments = [
        "diff",
        "--no-ext-diff",
        "--numstat",
    ]

    if normalized_baseline is not None:
        numstat_arguments.append(normalized_baseline)

    code, numstat, stderr = _run_git(
        root,
        numstat_arguments,
        timeout=timeout,
    )

    if code != 0:
        raise GitDiffCollectionError(
            f"Git numstat failed: {_redact(stderr.strip())}"
        )

    status_entries = _parse_name_status(name_status)
    stats = _parse_numstat(numstat)

    files: list[GitDiffFile] = []

    for status, path, old_path in status_entries:
        additions, deletions, binary = stats.get(
            path,
            (0, 0, False),
        )

        files.append(
            GitDiffFile(
                path=path,
                status=status,
                old_path=old_path,
                additions=additions,
                deletions=deletions,
                binary=binary,
            )
        )

    # Untracked files are not part of `git diff`, so collect them separately.
    if include_untracked:
        for line in status_output.splitlines():
            if not line.startswith("??"):
                continue

            path = line[3:].strip()

            if path:
                files.append(
                    GitDiffFile(
                        path=path,
                        status="untracked",
                    )
                )

    # Remove duplicate entries while preserving order.
    unique_files: list[GitDiffFile] = []
    seen: set[tuple[str, str, str | None]] = set()

    for item in files:
        key = (item.status, item.path, item.old_path)

        if key in seen:
            continue

        seen.add(key)
        unique_files.append(item)

    additions = sum(item.additions for item in unique_files)
    deletions = sum(item.deletions for item in unique_files)

    return GitDiffCollectionResult(
        repository_root=str(root),
        baseline=normalized_baseline,
        files=tuple(unique_files),
        additions=additions,
        deletions=deletions,
        changed_files=len(unique_files),
        raw_diff=_redact(raw_diff),
        status_output=_redact(status_output),
    )


def validate_git_diff_collection(
    result: GitDiffCollectionResult,
) -> bool:
    if not isinstance(result, GitDiffCollectionResult):
        return False

    try:
        GitDiffCollectionResult(
            repository_root=result.repository_root,
            baseline=result.baseline,
            files=result.files,
            additions=result.additions,
            deletions=result.deletions,
            changed_files=result.changed_files,
            raw_diff=result.raw_diff,
            status_output=result.status_output,
        )
    except (GitDiffCollectionError, TypeError, ValueError):
        return False

    return True


# Explicit public alias for callers that use the Task 216 terminology.
collect_git_diff_collection = collect_git_diff
