from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess


class ExistingChangeProtectionError(RuntimeError):
    """Raised when existing-change protection cannot be evaluated."""


@dataclass(frozen=True)
class ProtectedChange:
    relative_path: str
    status: str
    fingerprint: str


@dataclass(frozen=True)
class ExistingChangeProtection:
    repository_root: str
    changes: tuple[ProtectedChange, ...]


@dataclass(frozen=True)
class ProtectionValidationResult:
    valid: bool
    protected: bool
    violations: tuple[str, ...]
    reason: str


def _git(root: Path, *args: str, timeout: float) -> str:
    try:
        result = subprocess.run(
            ("git", *args),
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExistingChangeProtectionError(
            "GIT_COMMAND_UNAVAILABLE"
        ) from error

    if result.returncode != 0:
        raise ExistingChangeProtectionError(
            f"GIT_COMMAND_FAILED:{result.stderr.strip()}"
        )

    return result.stdout


def _repository_root(
    start_path: str | os.PathLike[str],
    timeout: float,
) -> Path:
    candidate = Path(start_path).expanduser().resolve()

    if not candidate.exists() or not candidate.is_dir():
        raise ExistingChangeProtectionError(
            "REPOSITORY_ROOT_INVALID"
        )

    output = _git(
        candidate,
        "rev-parse",
        "--show-toplevel",
        timeout=timeout,
    ).strip()

    root = Path(output).resolve()

    if not root.exists() or not root.is_dir():
        raise ExistingChangeProtectionError(
            "REPOSITORY_ROOT_INVALID"
        )

    return root


def _status_entries(
    root: Path,
    timeout: float,
) -> tuple[tuple[str, str], ...]:
    output = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        timeout=timeout,
    )

    entries: list[tuple[str, str]] = []

    for line in output.splitlines():
        if not line:
            continue

        if len(line) < 3:
            raise ExistingChangeProtectionError(
                "INVALID_GIT_STATUS_ENTRY"
            )

        status = line[:2]
        path_text = line[3:]

        if " -> " in path_text:
            path_text = path_text.split(" -> ", 1)[1]

        if not path_text:
            raise ExistingChangeProtectionError(
                "EMPTY_GIT_STATUS_PATH"
            )

        entries.append((path_text, status))

    return tuple(entries)


def _fingerprint(path: Path) -> str:
    try:
        # lstat/readlink are essential here:
        # symlink content must be fingerprinted as the link itself,
        # not as its target.
        if path.is_symlink():
            target = os.readlink(path)
            payload = (
                b"SYMLINK\0"
                + target.encode("utf-8", "surrogateescape")
            )
            return hashlib.sha256(payload).hexdigest()

        if path.is_file():
            digest = hashlib.sha256()
            digest.update(b"FILE\0")

            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)

            return digest.hexdigest()

        if path.is_dir():
            digest = hashlib.sha256()
            digest.update(b"DIRECTORY\0")

            for child in sorted(
                path.iterdir(),
                key=lambda item: item.name,
            ):
                digest.update(
                    child.name.encode(
                        "utf-8",
                        "surrogateescape",
                    )
                )
                digest.update(b"\0")
                digest.update(
                    _fingerprint(child).encode("ascii")
                )
                digest.update(b"\0")

            return digest.hexdigest()

        stat_result = path.lstat()
        payload = (
            f"OTHER\0{stat_result.st_mode}\0"
            f"{stat_result.st_size}\0"
        ).encode()

        return hashlib.sha256(payload).hexdigest()

    except OSError as error:
        raise ExistingChangeProtectionError(
            f"FINGERPRINT_FAILED:{path}"
        ) from error


def _tracked_paths(
    root: Path,
    timeout: float,
) -> tuple[str, ...]:
    output = _git(
        root,
        "ls-files",
        "-z",
        timeout=timeout,
    )

    paths = tuple(
        item
        for item in output.split("\0")
        if item
    )

    return paths


def capture_existing_change_protection(
    start_path: str | os.PathLike[str],
    timeout: float = 10.0,
) -> ExistingChangeProtection:
    if timeout <= 0:
        raise ExistingChangeProtectionError(
            "INVALID_TIMEOUT"
        )

    root = _repository_root(start_path, timeout)

    status_entries = _status_entries(root, timeout)
    protected_paths = {
        relative_path
        for relative_path, _ in status_entries
    }

    # Important:
    # Existing tracked symlinks must also be protected even when
    # git status is clean. Otherwise changing a clean symlink target
    # would be invisible to the protection layer.
    for relative_path in _tracked_paths(root, timeout):
        candidate = root / relative_path

        if candidate.is_symlink():
            protected_paths.add(relative_path)

    changes: list[ProtectedChange] = []

    status_map = dict(status_entries)

    for relative_path in sorted(protected_paths):
        candidate = root / relative_path

        if not candidate.exists() and not candidate.is_symlink():
            fingerprint = "<MISSING>"
        else:
            fingerprint = _fingerprint(candidate)

        changes.append(
            ProtectedChange(
                relative_path=relative_path,
                status=status_map.get(relative_path, "  "),
                fingerprint=fingerprint,
            )
        )

    return ExistingChangeProtection(
        repository_root=str(root),
        changes=tuple(changes),
    )


def validate_existing_change_protection(
    protection: ExistingChangeProtection,
    timeout: float = 10.0,
) -> ProtectionValidationResult:
    if not isinstance(
        protection,
        ExistingChangeProtection,
    ):
        raise ExistingChangeProtectionError(
            "INVALID_PROTECTION_OBJECT"
        )

    if timeout <= 0:
        raise ExistingChangeProtectionError(
            "INVALID_TIMEOUT"
        )

    root = Path(protection.repository_root).resolve()

    if not root.exists() or not root.is_dir():
        return ProtectionValidationResult(
            valid=False,
            protected=False,
            violations=("REPOSITORY_ROOT_MISSING",),
            reason="REPOSITORY_ROOT_MISSING",
        )

    current_entries = dict(
        _status_entries(root, timeout)
    )

    violations: list[str] = []

    for protected in protection.changes:
        relative_path = protected.relative_path
        candidate = root / relative_path

        # Explicit deletion detection.
        if not candidate.exists() and not candidate.is_symlink():
            violations.append(
                f"PROTECTED_CHANGE_MISSING:{relative_path}"
            )
            continue

        current_status = current_entries.get(
            relative_path,
            "  ",
        )

        if current_status != protected.status:
            violations.append(
                "PROTECTED_STATUS_CHANGED:"
                f"{relative_path}:"
                f"{protected.status!r}->{current_status!r}"
            )

        current_fingerprint = _fingerprint(candidate)

        if current_fingerprint != protected.fingerprint:
            violations.append(
                f"PROTECTED_CONTENT_CHANGED:{relative_path}"
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
        reason="EXISTING_CHANGE_PROTECTION_PASSED",
    )


def require_existing_change_protection(
    protection: ExistingChangeProtection,
    timeout: float = 10.0,
) -> ProtectionValidationResult:
    result = validate_existing_change_protection(
        protection,
        timeout=timeout,
    )

    if not result.protected:
        raise ExistingChangeProtectionError(
            ";".join(result.violations)
        )

    return result
