from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence


class LockfileRegenerationError(ValueError):
    """Raised when lockfile regeneration input is unsafe or invalid."""


SUPPORTED_REGENERATION_COMMANDS = {
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
    "yarn": {
        "package.json": (
            "yarn",
            "install",
            "--mode=skip-builds",
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
            "--no-update",
        ),
    },
}


MANIFEST_TO_LOCKFILE = {
    "npm": ("package.json", "package-lock.json"),
    "yarn": ("package.json", "yarn.lock"),
    "pnpm": ("package.json", "pnpm-lock.yaml"),
    "cargo": ("Cargo.toml", "Cargo.lock"),
    "go": ("go.mod", "go.sum"),
    "composer": ("composer.json", "composer.lock"),
    "poetry": ("pyproject.toml", "poetry.lock"),
}


@dataclass(frozen=True)
class LockfileRegenerationRequest:
    repository_root: Path
    ecosystem: str
    manifest: Path
    lockfile: Path
    package_manager: str
    timeout: float = 300.0
    environment: Optional[Mapping[str, str]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise TypeError("repository_root must be pathlib.Path")

        if not isinstance(self.manifest, Path):
            raise TypeError("manifest must be pathlib.Path")

        if not isinstance(self.lockfile, Path):
            raise TypeError("lockfile must be pathlib.Path")

        if not isinstance(self.ecosystem, str) or not self.ecosystem.strip():
            raise LockfileRegenerationError(
                "ecosystem must be a non-empty string"
            )

        if not isinstance(self.package_manager, str):
            raise TypeError("package_manager must be str")

        if not self.package_manager.strip():
            raise LockfileRegenerationError(
                "package_manager cannot be empty"
            )

        if isinstance(self.timeout, bool) or not isinstance(
            self.timeout, (int, float)
        ):
            raise TypeError("timeout must be numeric")

        if self.timeout <= 0:
            raise LockfileRegenerationError(
                "timeout must be greater than zero"
            )


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


def _resolve_inside(root: Path, candidate: Path) -> Path:
    try:
        root_resolved = root.resolve(strict=True)
    except OSError as exc:
        raise LockfileRegenerationError(
            f"repository root cannot be resolved: {root}"
        ) from exc

    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise LockfileRegenerationError(
            f"path cannot be resolved: {candidate}"
        ) from exc

    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise LockfileRegenerationError(
            f"path is outside repository: {candidate}"
        ) from exc

    return resolved


def _validate_repository(root: Path) -> Path:
    if not root.exists():
        raise LockfileRegenerationError(
            f"repository root does not exist: {root}"
        )

    if not root.is_dir():
        raise LockfileRegenerationError(
            f"repository root is not a directory: {root}"
        )

    return root.resolve()


def _validate_regular_target(
    root: Path,
    path: Path,
    *,
    allow_missing: bool,
) -> Path:
    resolved = _resolve_inside(root, path)

    if resolved.is_symlink():
        raise LockfileRegenerationError(
            f"symlink target is not allowed: {path}"
        )

    if resolved.exists() and not resolved.is_file():
        raise LockfileRegenerationError(
            f"path is not a regular file: {path}"
        )

    if not allow_missing and not resolved.exists():
        raise LockfileRegenerationError(
            f"required file does not exist: {path}"
        )

    return resolved


def _fingerprint(path: Path) -> LockfileFingerprint:
    if not path.exists():
        return LockfileFingerprint(
            exists=False,
            is_file=False,
            is_symlink=path.is_symlink(),
            size=0,
            sha256=None,
        )

    if path.is_symlink():
        return LockfileFingerprint(
            exists=True,
            is_file=False,
            is_symlink=True,
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
    root = _validate_repository(repository_root)

    normalized = ecosystem.strip().lower()

    if normalized not in MANIFEST_TO_LOCKFILE:
        raise LockfileRegenerationError(
            f"unsupported ecosystem: {ecosystem}"
        )

    _, lock_name = MANIFEST_TO_LOCKFILE[normalized]
    return root / lock_name


def build_regeneration_command(
    ecosystem: str,
    package_manager: str,
    manifest: Path,
    lockfile: Path,
) -> tuple[str, ...]:
    normalized_ecosystem = ecosystem.strip().lower()
    normalized_manager = package_manager.strip().lower()

    if normalized_ecosystem not in SUPPORTED_REGENERATION_COMMANDS:
        raise LockfileRegenerationError(
            f"unsupported ecosystem: {ecosystem}"
        )

    if normalized_manager != normalized_ecosystem:
        raise LockfileRegenerationError(
            "package manager does not match ecosystem"
        )

    manifest_name = manifest.name

    command_map = SUPPORTED_REGENERATION_COMMANDS[
        normalized_ecosystem
    ]

    if manifest_name not in command_map:
        raise LockfileRegenerationError(
            f"unsupported manifest for {normalized_manager}: "
            f"{manifest_name}"
        )

    command = command_map[manifest_name]

    if not command:
        raise LockfileRegenerationError(
            "regeneration command cannot be empty"
        )

    if any(not isinstance(part, str) or not part for part in command):
        raise LockfileRegenerationError(
            "regeneration command contains invalid arguments"
        )

    return tuple(command)


def validate_regeneration_request(
    request: LockfileRegenerationRequest,
) -> tuple[Path, Path, tuple[str, ...]]:
    root = _validate_repository(request.repository_root)

    manifest = _validate_regular_target(
        root,
        request.manifest,
        allow_missing=False,
    )

    lockfile = _validate_regular_target(
        root,
        request.lockfile,
        allow_missing=True,
    )

    expected = expected_lockfile(root, request.ecosystem)

    if lockfile != expected:
        raise LockfileRegenerationError(
            f"unexpected lockfile for ecosystem: {lockfile}"
        )

    command = build_regeneration_command(
        request.ecosystem,
        request.package_manager,
        manifest,
        lockfile,
    )

    return root, manifest, command


def _prepare_environment(
    custom_environment: Optional[Mapping[str, str]],
) -> dict[str, str]:
    environment = dict(os.environ)

    if custom_environment is not None:
        for key, value in custom_environment.items():
            if not isinstance(key, str) or not key:
                raise LockfileRegenerationError(
                    "environment variable name must be non-empty string"
                )

            if "\x00" in key:
                raise LockfileRegenerationError(
                    "environment variable name contains NULL"
                )

            if not isinstance(value, str):
                raise TypeError(
                    "environment variable value must be string"
                )

            if "\x00" in value:
                raise LockfileRegenerationError(
                    "environment variable value contains NULL"
                )

            environment[key] = value

    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONUNBUFFERED"] = "1"

    return environment


def regenerate_lockfile(
    request: LockfileRegenerationRequest,
) -> LockfileRegenerationResult:
    root, manifest, command = validate_regeneration_request(request)

    lockfile = _validate_regular_target(
        root,
        request.lockfile,
        allow_missing=True,
    )

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
            reason=f"PACKAGE_MANAGER_NOT_AVAILABLE:{command[0]}",
        )

    environment = _prepare_environment(request.environment)

    try:
        completed = subprocess.run(
            list(command),
            cwd=root,
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
            stdout=(
                exc.stdout.decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            ),
            stderr=(
                exc.stderr.decode(errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            ),
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

    if not after.exists or not after.is_file:
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
            reason="LOCKFILE_NOT_PRESENT_AFTER_REGENERATION",
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

    if after.size == 0:
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
            reason="LOCKFILE_EMPTY_AFTER_REGENERATION",
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


def validate_lockfile_result(
    result: LockfileRegenerationResult,
) -> bool:
    if not isinstance(result, LockfileRegenerationResult):
        raise TypeError("result must be LockfileRegenerationResult")

    if not result.success:
        return False

    if result.return_code != 0:
        return False

    if result.timed_out:
        return False

    if not result.after.exists:
        return False

    if not result.after.is_file:
        return False

    if result.after.is_symlink:
        return False

    if result.after.size <= 0:
        return False

    return True
