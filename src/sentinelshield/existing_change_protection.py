from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import subprocess
from typing import Optional


@dataclass(frozen=True)
class ProtectedChange:
    path: str
    status: str
    fingerprint: str


@dataclass(frozen=True)
class ExistingChangeProtection:
    repository_root: Path
    changes: tuple[ProtectedChange, ...]
    valid: bool
    reason: str


@dataclass(frozen=True)
class ProtectionValidationResult:
    valid: bool
    protected: bool
    violations: tuple[str, ...]
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

    return Path(value).resolve()


def _status_lines(
    repository_root: Path,
    timeout: float,
) -> tuple[str, ...]:
    result = _run_git(
        repository_root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--no-renames",
        ],
        timeout,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"git status failed: {result.stderr.strip()}"
        )

    return tuple(
        line
        for line in result.stdout.splitlines()
        if line
    )


def _fingerprint_path(
    repository_root: Path,
    relative_path: str,
) -> str:
    path = repository_root / relative_path

    if not path.exists() and not path.is_symlink():
        return "MISSING"

    if path.is_symlink():
        target = path.readlink().as_posix()
        return "SYMLINK:" + sha256(
            target.encode("utf-8")
        ).hexdigest()

    if path.is_file():
        digest = sha256()

        with path.open("rb") as handle:
            for chunk in iter(
                lambda: handle.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return "FILE:" + digest.hexdigest()

    if path.is_dir():
        digest = sha256()

        entries = sorted(
            child
            for child in path.rglob("*")
            if child.is_file() or child.is_symlink()
        )

        for child in entries:
            relative = child.relative_to(repository_root).as_posix()

            if child.is_symlink():
                content = (
                    "SYMLINK:"
                    + child.readlink().as_posix()
                ).encode("utf-8")
            else:
                child_digest = sha256()
                with child.open("rb") as handle:
                    for chunk in iter(
                        lambda: handle.read(1024 * 1024),
                        b"",
                    ):
                        child_digest.update(chunk)

                content = (
                    "FILE:"
                    + child_digest.hexdigest()
                ).encode("utf-8")

            digest.update(
                relative.encode("utf-8")
            )
            digest.update(b"\0")
            digest.update(content)
            digest.update(b"\0")

        return "DIR:" + digest.hexdigest()

    try:
        metadata = path.stat()
        value = (
            f"MODE:{metadata.st_mode}:"
            f"SIZE:{metadata.st_size}"
        )
    except OSError as error:
        value = f"STAT_ERROR:{error}"

    return "OTHER:" + sha256(
        value.encode("utf-8")
    ).hexdigest()


def _parse_status_line(
    line: str,
) -> tuple[str, str]:
    if len(line) < 3:
        raise ValueError(
            f"Invalid porcelain status line: {line!r}"
        )

    return line[:2], line[3:]


def capture_existing_change_protection(
    start_path: str | Path,
    timeout: float = 10.0,
) -> ExistingChangeProtection:
    try:
        start = Path(start_path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError) as error:
        return ExistingChangeProtection(
            repository_root=Path(".").resolve(),
            changes=(),
            valid=False,
            reason=f"INVALID_START_PATH: {error}",
        )

    if not start.exists():
        return ExistingChangeProtection(
            repository_root=start,
            changes=(),
            valid=False,
            reason="START_PATH_NOT_FOUND",
        )

    if not start.is_dir():
        return ExistingChangeProtection(
            repository_root=start,
            changes=(),
            valid=False,
            reason="START_PATH_NOT_DIRECTORY",
        )

    try:
        root = _repository_root(start, timeout)
    except subprocess.TimeoutExpired:
        return ExistingChangeProtection(
            repository_root=start,
            changes=(),
            valid=False,
            reason="GIT_ROOT_TIMEOUT",
        )
    except OSError as error:
        return ExistingChangeProtection(
            repository_root=start,
            changes=(),
            valid=False,
            reason=f"GIT_ROOT_EXECUTION_ERROR: {error}",
        )

    if root is None:
        return ExistingChangeProtection(
            repository_root=start,
            changes=(),
            valid=False,
            reason="NOT_A_GIT_REPOSITORY",
        )

    try:
        lines = _status_lines(root, timeout)
    except subprocess.TimeoutExpired:
        return ExistingChangeProtection(
            repository_root=root,
            changes=(),
            valid=False,
            reason="GIT_STATUS_TIMEOUT",
        )
    except (OSError, RuntimeError) as error:
        return ExistingChangeProtection(
            repository_root=root,
            changes=(),
            valid=False,
            reason=f"GIT_STATUS_ERROR: {error}",
        )

    protected: list[ProtectedChange] = []

    try:
        for line in lines:
            status, relative_path = _parse_status_line(line)

            fingerprint = _fingerprint_path(
                root,
                relative_path,
            )

            protected.append(
                ProtectedChange(
                    path=relative_path,
                    status=status,
                    fingerprint=fingerprint,
                )
            )
    except (OSError, ValueError, RuntimeError) as error:
        return ExistingChangeProtection(
            repository_root=root,
            changes=(),
            valid=False,
            reason=f"PROTECTION_CAPTURE_ERROR: {error}",
        )

    return ExistingChangeProtection(
        repository_root=root,
        changes=tuple(protected),
        valid=True,
        reason=(
            "EXISTING_CHANGES_CAPTURED"
            if protected
            else "NO_EXISTING_CHANGES"
        ),
    )


def validate_existing_change_protection(
    protection: ExistingChangeProtection,
    timeout: float = 10.0,
) -> ProtectionValidationResult:
    if not protection.valid:
        return ProtectionValidationResult(
            valid=False,
            protected=False,
            violations=(
                f"INVALID_PROTECTION_STATE: {protection.reason}",
            ),
            reason="INVALID_PROTECTION_STATE",
        )

    root = protection.repository_root

    if not root.exists() or not root.is_dir():
        return ProtectionValidationResult(
            valid=False,
            protected=False,
            violations=("REPOSITORY_ROOT_UNAVAILABLE",),
            reason="REPOSITORY_ROOT_UNAVAILABLE",
        )

    try:
        current_lines = _status_lines(root, timeout)
    except subprocess.TimeoutExpired:
        return ProtectionValidationResult(
            valid=False,
            protected=False,
            violations=("GIT_STATUS_TIMEOUT",),
            reason="GIT_STATUS_TIMEOUT",
        )
    except (OSError, RuntimeError) as error:
        return ProtectionValidationResult(
            valid=False,
            protected=False,
            violations=(f"GIT_STATUS_ERROR: {error}",),
            reason="GIT_STATUS_ERROR",
        )

    current_by_path: dict[str, tuple[str, str]] = {}

    try:
        for line in current_lines:
            status, relative_path = _parse_status_line(line)

            current_by_path[relative_path] = (
                status,
                _fingerprint_path(
                    root,
                    relative_path,
                ),
            )
    except (OSError, ValueError, RuntimeError) as error:
        return ProtectionValidationResult(
            valid=False,
            protected=False,
            violations=(
                f"PROTECTION_VALIDATION_ERROR: {error}",
            ),
            reason="PROTECTION_VALIDATION_ERROR",
        )

    violations: list[str] = []

    for protected_change in protection.changes:
        current = current_by_path.get(
            protected_change.path
        )

        if current is None:
            violations.append(
                "PROTECTED_CHANGE_MISSING:"
                f"{protected_change.path}"
            )
            continue

        current_status, current_fingerprint = current

        if current_status != protected_change.status:
            violations.append(
                "PROTECTED_STATUS_CHANGED:"
                f"{protected_change.path}:"
                f"{protected_change.status!r}->"
                f"{current_status!r}"
            )

        if current_fingerprint != protected_change.fingerprint:
            violations.append(
                "PROTECTED_CONTENT_CHANGED:"
                f"{protected_change.path}"
            )

    if violations:
        return ProtectionValidationResult(
            valid=True,
            protected=False,
            violations=tuple(violations),
            reason="EXISTING_CHANGE_PROTECTION_FAILED",
        )

    return ProtectionValidationResult(
        valid=True,
        protected=True,
        violations=(),
        reason=(
            "EXISTING_CHANGES_PROTECTED"
            if protection.changes
            else "NO_EXISTING_CHANGES_TO_PROTECT"
        ),
    )


__all__ = [
    "ProtectedChange",
    "ExistingChangeProtection",
    "ProtectionValidationResult",
    "capture_existing_change_protection",
    "validate_existing_change_protection",
]
