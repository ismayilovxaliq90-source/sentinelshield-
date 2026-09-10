from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence


class LockfileRegenerationError(ValueError):
    """Raised when lockfile regeneration cannot be safely performed."""


@dataclass(frozen=True)
class LockfileFingerprint:
    exists: bool
    is_file: bool
    is_symlink: bool
    size: int
    sha256: Optional[str]

    def to_dict(self) -> dict:
        return {
            "exists": self.exists,
            "is_file": self.is_file,
            "is_symlink": self.is_symlink,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class LockfileRegenerationRequest:
    repository_root: Path
    ecosystem: str
    package_manager: str
    manifest: Path
    lockfile: Path
    timeout: float = 300.0
    environment: Optional[Mapping[str, str]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise TypeError("repository_root must be Path")

        if not isinstance(self.manifest, Path):
            raise TypeError("manifest must be Path")

        if not isinstance(self.lockfile, Path):
            raise TypeError("lockfile must be Path")

        if not isinstance(self.ecosystem, str):
            raise TypeError("ecosystem must be str")

        if not self.ecosystem.strip():
            raise LockfileRegenerationError(
                "ecosystem cannot be empty"
            )

        if not isinstance(self.package_manager, str):
            raise TypeError("package_manager must be str")

        if not self.package_manager.strip():
            raise LockfileRegenerationError(
                "package_manager cannot be empty"
            )

        if isinstance(self.timeout, bool):
            raise TypeError("timeout must be numeric")

        if not isinstance(self.timeout, (int, float)):
            raise TypeError("timeout must be numeric")

        if self.timeout <= 0:
            raise LockfileRegenerationError(
                "timeout must be greater than zero"
            )


@dataclass(frozen=True)
class LockfileRegenerationResult:
    success: bool
    ecosystem: str
    package_manager: str
    manifest: Path
    lockfile: Path
    command: tuple[str, ...]
    return_code: Optional[int]
    timed_out: bool
    changed: bool
    before: LockfileFingerprint
    after: LockfileFingerprint
    stdout: str
    stderr: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "ecosystem": self.ecosystem,
            "package_manager": self.package_manager,
            "manifest": str(self.manifest),
            "lockfile": str(self.lockfile),
            "command": list(self.command),
            "return_code": self.return_code,
            "timed_out": self.timed_out,
            "changed": self.changed,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "reason": self.reason,
        }


# Commands are immutable and allowlisted.
# No arbitrary command can be supplied by the caller.
_COMMANDS: dict[str, dict[str, tuple[str, ...]]] = {
    "npm": {
        "package.json": (
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ),
    },
    "pnpm": {
        "package.json": (
            "pnpm",
            "install",
            "--lockfile-only",
            "--ignore-scripts",
        ),
    },
    "yarn": {
        "package.json": (
            "yarn",
            "install",
            "--mode=skip-builds",
        ),
    },
    "cargo": {
        "Cargo.toml": (
            "cargo",
            "generate-lockfile",
        ),
    },
    "go": {
        "go.mod": (
            "go",
            "mod",
            "tidy",
        ),
    },
    "composer": {
        "composer.json": (
            "composer",
            "update",
            "--lock",
            "--no-interaction",
            "--no-scripts",
        ),
    },
    "poetry": {
        "pyproject.toml": (
            "poetry",
            "lock",
        ),
    },
}


_EXPECTED_LOCKFILES: dict[str, tuple[str, str]] = {
    "npm": ("package.json", "package-lock.json"),
    "pnpm": ("package.json", "pnpm-lock.yaml"),
    "yarn": ("package.json", "yarn.lock"),
    "cargo": ("Cargo.toml", "Cargo.lock"),
    "go": ("go.mod", "go.sum"),
    "composer": ("composer.json", "composer.lock"),
    "poetry": ("pyproject.toml", "poetry.lock"),
}


def _repository_root(path: Path) -> Path:
    if not path.exists():
        raise LockfileRegenerationError(
            f"repository does not exist: {path}"
        )

    if not path.is_dir():
        raise LockfileRegenerationError(
            f"repository is not a directory: {path}"
        )

    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise LockfileRegenerationError(
            "unable to resolve repository root"
        ) from exc


def _inside(root: Path, path: Path) -> Path:
    # Reject the symlink itself before resolve().
    if path.is_symlink():
        raise LockfileRegenerationError(
            f"symlink path is forbidden: {path}"
        )

    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise LockfileRegenerationError(
            f"path is outside repository: {path}"
        ) from exc

    return resolved


def _validate_manifest(root: Path, manifest: Path) -> Path:
    resolved = _inside(root, manifest)

    if not resolved.exists():
        raise LockfileRegenerationError(
            f"manifest does not exist: {manifest}"
        )

    if not resolved.is_file():
        raise LockfileRegenerationError(
            f"manifest is not a regular file: {manifest}"
        )

    return resolved


def _validate_lockfile(
    root: Path,
    lockfile: Path,
) -> Path:
    resolved = _inside(root, lockfile)

    if resolved.exists() and not resolved.is_file():
        raise LockfileRegenerationError(
            f"lockfile is not a regular file: {lockfile}"
        )

    return resolved


def _fingerprint(path: Path) -> LockfileFingerprint:
    if path.is_symlink():
        return LockfileFingerprint(
            exists=True,
            is_file=False,
            is_symlink=True,
            size=0,
            sha256=None,
        )

    if not path.exists():
        return LockfileFingerprint(
            exists=False,
            is_file=False,
            is_symlink=False,
            size=0,
            sha256=None,
        )

    if not path.is_file():
        return LockfileFingerprint(
            exists=True,
            is_file=False,
            is_symlink=False,
            size=0,
            sha256=None,
        )

    digest = hashlib.sha256()
    size = 0

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)
                size += len(chunk)

    except OSError as exc:
        raise LockfileRegenerationError(
            f"unable to fingerprint lockfile: {path}"
        ) from exc

    return LockfileFingerprint(
        exists=True,
        is_file=True,
        is_symlink=False,
        size=size,
        sha256=digest.hexdigest(),
    )


def expected_lockfile(
    repository_root: Path,
    ecosystem: str,
) -> Path:
    root = _repository_root(repository_root)

    ecosystem_name = ecosystem.strip().lower()

    if ecosystem_name not in _EXPECTED_LOCKFILES:
        raise LockfileRegenerationError(
            f"unsupported ecosystem: {ecosystem}"
        )

    return root / _EXPECTED_LOCKFILES[ecosystem_name][1]


def build_regeneration_command(
    ecosystem: str,
    package_manager: str,
    manifest: Path,
) -> tuple[str, ...]:
    ecosystem_name = ecosystem.strip().lower()
    manager_name = package_manager.strip().lower()

    if ecosystem_name not in _COMMANDS:
        raise LockfileRegenerationError(
            f"unsupported ecosystem: {ecosystem}"
        )

    if manager_name != ecosystem_name:
        raise LockfileRegenerationError(
            "package manager does not match ecosystem"
        )

    commands = _COMMANDS[ecosystem_name]

    if manifest.name not in commands:
        raise LockfileRegenerationError(
            f"unsupported manifest: {manifest.name}"
        )

    command = commands[manifest.name]

    if not command:
        raise LockfileRegenerationError(
            "empty regeneration command"
        )

    if any(
        not isinstance(argument, str) or not argument
        for argument in command
    ):
        raise LockfileRegenerationError(
            "invalid command argument"
        )

    return command


def validate_request(
    request: LockfileRegenerationRequest,
) -> tuple[Path, Path, Path, tuple[str, ...]]:
    root = _repository_root(request.repository_root)

    manifest = _validate_manifest(
        root,
        request.manifest,
    )

    lockfile = _validate_lockfile(
        root,
        request.lockfile,
    )

    expected = expected_lockfile(
        root,
        request.ecosystem,
    )

    if lockfile != expected:
        raise LockfileRegenerationError(
            "lockfile does not match ecosystem"
        )

    command = build_regeneration_command(
        request.ecosystem,
        request.package_manager,
        manifest,
    )

    return root, manifest, lockfile, command


def _environment(
    custom: Optional[Mapping[str, str]],
) -> dict[str, str]:
    result = dict(os.environ)

    if custom is not None:
        for key, value in custom.items():
            if not isinstance(key, str):
                raise TypeError(
                    "environment variable name must be str"
                )

            if not key or "\x00" in key:
                raise LockfileRegenerationError(
                    "invalid environment variable name"
                )

            if not isinstance(value, str):
                raise TypeError(
                    "environment variable value must be str"
                )

            if "\x00" in value:
                raise LockfileRegenerationError(
                    "environment variable contains NULL"
                )

            result[key] = value

    # Prevent Python bytecode from changing the repository.
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    result["PYTHONUNBUFFERED"] = "1"

    return result


def regenerate_lockfile(
    request: LockfileRegenerationRequest,
) -> LockfileRegenerationResult:
    root, manifest, lockfile, command = validate_request(request)

    before = _fingerprint(lockfile)

    executable = shutil.which(command[0])

    if executable is None:
        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=None,
            timed_out=False,
            changed=False,
            before=before,
            after=before,
            stdout="",
            stderr="",
            reason=f"PACKAGE_MANAGER_NOT_FOUND:{command[0]}",
        )

    environment = _environment(request.environment)

    try:
        completed = subprocess.run(
            list(command),
            cwd=str(root),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            close_fds=True,
            timeout=float(request.timeout),
            check=False,
        )

    except subprocess.TimeoutExpired as exc:
        after = _fingerprint(lockfile)

        stdout = (
            exc.stdout.decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )

        stderr = (
            exc.stderr.decode(errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )

        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=None,
            timed_out=True,
            changed=before != after,
            before=before,
            after=after,
            stdout=stdout,
            stderr=stderr,
            reason="REGENERATION_TIMEOUT",
        )

    except OSError as exc:
        after = _fingerprint(lockfile)

        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=None,
            timed_out=False,
            changed=before != after,
            before=before,
            after=after,
            stdout="",
            stderr=str(exc),
            reason="REGENERATION_EXECUTION_ERROR",
        )

    after = _fingerprint(lockfile)
    changed = before != after

    if completed.returncode != 0:
        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=completed.returncode,
            timed_out=False,
            changed=changed,
            before=before,
            after=after,
            stdout=completed.stdout,
            stderr=completed.stderr,
            reason="REGENERATION_COMMAND_FAILED",
        )

    if not after.exists:
        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=completed.returncode,
            timed_out=False,
            changed=changed,
            before=before,
            after=after,
            stdout=completed.stdout,
            stderr=completed.stderr,
            reason="LOCKFILE_NOT_CREATED",
        )

    if not after.is_file:
        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=completed.returncode,
            timed_out=False,
            changed=changed,
            before=before,
            after=after,
            stdout=completed.stdout,
            stderr=completed.stderr,
            reason="LOCKFILE_NOT_REGULAR_FILE",
        )

    if after.is_symlink:
        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=completed.returncode,
            timed_out=False,
            changed=changed,
            before=before,
            after=after,
            stdout=completed.stdout,
            stderr=completed.stderr,
            reason="LOCKFILE_SYMLINK_FORBIDDEN",
        )

    if after.size <= 0:
        return LockfileRegenerationResult(
            success=False,
            ecosystem=request.ecosystem,
            package_manager=request.package_manager,
            manifest=manifest,
            lockfile=lockfile,
            command=command,
            return_code=completed.returncode,
            timed_out=False,
            changed=changed,
            before=before,
            after=after,
            stdout=completed.stdout,
            stderr=completed.stderr,
            reason="LOCKFILE_EMPTY",
        )

    return LockfileRegenerationResult(
        success=True,
        ecosystem=request.ecosystem,
        package_manager=request.package_manager,
        manifest=manifest,
        lockfile=lockfile,
        command=command,
        return_code=completed.returncode,
        timed_out=False,
        changed=changed,
        before=before,
        after=after,
        stdout=completed.stdout,
        stderr=completed.stderr,
        reason="LOCKFILE_REGENERATED",
    )


def validate_regeneration_result(
    result: LockfileRegenerationResult,
) -> bool:
    if not isinstance(result, LockfileRegenerationResult):
        raise TypeError(
            "result must be LockfileRegenerationResult"
        )

    return bool(
        result.success
        and result.return_code == 0
        and not result.timed_out
        and result.after.exists
        and result.after.is_file
        and not result.after.is_symlink
        and result.after.size > 0
    )
