from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import subprocess
from typing import Optional


@dataclass(frozen=True)
class ExistingChange:
    status: str
    path: str
    content_hash: Optional[str]


@dataclass(frozen=True)
class ExistingChangeProtectionResult:
    valid: bool
    repository_root: Optional[Path]
    protected: bool
    existing_changes: tuple[ExistingChange, ...]
    change_count: int
    reason: str


def _run_git(
    repository_root: Path,
    arguments: list[str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository_root,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _repository_root(
    start_path: Path,
    timeout: float,
) -> Optional[Path]:
    result = _run_git(
        start_path,
        ["rev-parse", "--show-toplevel"],
        timeout,
    )

    if result.returncode != 0:
        return None

    value = result.stdout.strip()

    if not value:
        return None

    return Path(value)


def _parse_status(
    output: str,
) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []

    for line in output.splitlines():
        if not line or len(line) < 3:
            continue

        status = line[:2]
        path = line[3:]

        if "->" in path and status.endswith("R"):
            path = path.split("->", 1)[-1].strip()

        parsed.append((status, path))

    return parsed


def _sha256_file(
    path: Path,
) -> Optional[str]:
    try:
        if not path.is_file():
            return None

        digest = hashlib.sha256()

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    except (OSError, PermissionError):
        return None


def capture_existing_change_protection(
    start_path: str | Path,
    timeout: float = 10.0,
) -> ExistingChangeProtectionResult:
    try:
        start = Path(start_path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError) as error:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=None,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason=f"INVALID_START_PATH: {error}",
        )

    if not start.exists():
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=None,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason="START_PATH_NOT_FOUND",
        )

    if not start.is_dir():
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=None,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason="START_PATH_NOT_DIRECTORY",
        )

    try:
        root = _repository_root(start, timeout)
    except subprocess.TimeoutExpired:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=None,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason="GIT_REV_PARSE_TIMEOUT",
        )
    except OSError as error:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=None,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason=f"GIT_EXECUTION_ERROR: {error}",
        )

    if root is None:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=None,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason="NOT_A_GIT_REPOSITORY",
        )

    try:
        status = _run_git(
            root,
            [
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--no-renames",
            ],
            timeout,
        )
    except subprocess.TimeoutExpired:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=root,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason="GIT_STATUS_TIMEOUT",
        )
    except OSError as error:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=root,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason=f"GIT_STATUS_EXECUTION_ERROR: {error}",
        )

    if status.returncode != 0:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=root,
            protected=False,
            existing_changes=(),
            change_count=0,
            reason="GIT_STATUS_FAILED",
        )

    status_entries = _parse_status(status.stdout)

    changes: list[ExistingChange] = []

    for status_code, relative_path in status_entries:
        absolute_path = root / relative_path

        content_hash = None

        if status_code in {" M", "M ", "MM", "A ", "AM", "??"}:
            content_hash = _sha256_file(absolute_path)

        changes.append(
            ExistingChange(
                status=status_code,
                path=relative_path,
                content_hash=content_hash,
            )
        )

    protected = all(
        change.path and (
            change.status == "??"
            or change.content_hash is not None
            or change.status.strip() == ""
        )
        for change in changes
    )

    if not protected:
        reason = "EXISTING_CHANGE_PROTECTION_INCOMPLETE"
    elif changes:
        reason = "EXISTING_CHANGES_IDENTIFIED_AND_PROTECTED"
    else:
        reason = "NO_EXISTING_CHANGES"

    return ExistingChangeProtectionResult(
        valid=True,
        repository_root=root,
        protected=protected,
        existing_changes=tuple(changes),
        change_count=len(changes),
        reason=reason,
    )


def verify_existing_change_protection(
    before: ExistingChangeProtectionResult,
    start_path: str | Path,
    timeout: float = 10.0,
) -> ExistingChangeProtectionResult:
    current = capture_existing_change_protection(
        start_path,
        timeout=timeout,
    )

    if not before.valid:
        return ExistingChangeProtectionResult(
            valid=False,
            repository_root=current.repository_root,
            protected=False,
            existing_changes=current.existing_changes,
            change_count=current.change_count,
            reason="INVALID_BEFORE_PROTECTION_STATE",
        )

    if not current.valid:
        return current

    before_map = {
        change.path: change
        for change in before.existing_changes
    }

    current_map = {
        change.path: change
        for change in current.existing_changes
    }

    for path, baseline_change in before_map.items():
        current_change = current_map.get(path)

        if current_change is None:
            return ExistingChangeProtectionResult(
                valid=True,
                repository_root=current.repository_root,
                protected=False,
                existing_changes=current.existing_changes,
                change_count=current.change_count,
                reason=f"PRE_EXISTING_CHANGE_REMOVED: {path}",
            )

        if (
            baseline_change.content_hash is not None
            and current_change.content_hash is not None
            and baseline_change.content_hash != current_change.content_hash
        ):
            return ExistingChangeProtectionResult(
                valid=True,
                repository_root=current.repository_root,
                protected=False,
                existing_changes=current.existing_changes,
                change_count=current.change_count,
                reason=f"PRE_EXISTING_CHANGE_MODIFIED: {path}",
            )

    return ExistingChangeProtectionResult(
        valid=True,
        repository_root=current.repository_root,
        protected=True,
        existing_changes=current.existing_changes,
        change_count=current.change_count,
        reason="PRE_EXISTING_CHANGES_PRESERVED",
    )


__all__ = [
    "ExistingChange",
    "ExistingChangeProtectionResult",
    "capture_existing_change_protection",
    "verify_existing_change_protection",
]
