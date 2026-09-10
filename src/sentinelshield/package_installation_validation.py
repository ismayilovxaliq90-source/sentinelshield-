from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class PackageInstallationValidationError(RuntimeError):
    """Raised when package installation validation cannot be performed safely."""


SUPPORTED_MANAGERS = frozenset({"npm"})

MANIFESTS = {
    "npm": "package.json",
}

LOCKFILES = {
    "npm": "package-lock.json",
}


@dataclass(frozen=True)
class PackageInstallationRequest:
    repository_root: Path
    manager: str = "npm"
    timeout: float = 300.0
    environment: Mapping[str, str] | None = None


@dataclass(frozen=True)
class InstalledPackage:
    name: str
    version: str
    path: Path

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "path": str(self.path),
        }


@dataclass(frozen=True)
class PackageInstallationResult:
    success: bool
    manager: str
    command: tuple[str, ...]
    returncode: int | None
    installed: tuple[InstalledPackage, ...]
    expected_dependency_count: int
    actual_dependency_count: int
    lockfile_present: bool
    installation_directory_present: bool
    stdout: str
    stderr: str
    timed_out: bool
    error: str | None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "manager": self.manager,
            "command": list(self.command),
            "returncode": self.returncode,
            "installed": [
                package.to_dict()
                for package in self.installed
            ],
            "expected_dependency_count": self.expected_dependency_count,
            "actual_dependency_count": self.actual_dependency_count,
            "lockfile_present": self.lockfile_present,
            "installation_directory_present": (
                self.installation_directory_present
            ),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "error": self.error,
        }


def _resolve_root(path: Path) -> Path:
    if not isinstance(path, Path):
        raise PackageInstallationValidationError(
            "repository_root must be a Path"
        )

    try:
        root = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PackageInstallationValidationError(
            f"Unable to resolve repository root: {path}"
        ) from exc

    if not root.is_dir():
        raise PackageInstallationValidationError(
            f"Repository root is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise PackageInstallationValidationError(
            f"Not a Git repository: {root}"
        )

    return root


def _validate_manager(manager: str) -> str:
    if not isinstance(manager, str):
        raise PackageInstallationValidationError(
            "manager must be a string"
        )

    normalized = manager.strip().lower()

    if normalized not in SUPPORTED_MANAGERS:
        raise PackageInstallationValidationError(
            f"Unsupported package manager: {manager}"
        )

    return normalized


def _validate_timeout(timeout: float) -> None:
    if isinstance(timeout, bool):
        raise PackageInstallationValidationError(
            "Invalid timeout"
        )

    if not isinstance(timeout, (int, float)):
        raise PackageInstallationValidationError(
            "timeout must be numeric"
        )

    if timeout <= 0 or timeout > 1800:
        raise PackageInstallationValidationError(
            "timeout must be between 0 and 1800 seconds"
        )


def _regular_file(root: Path, relative: str) -> Path:
    path = root / relative

    if path.is_symlink():
        raise PackageInstallationValidationError(
            f"Symlink is not allowed: {path}"
        )

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PackageInstallationValidationError(
            f"Unable to resolve required file: {path}"
        ) from exc

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PackageInstallationValidationError(
            f"Required file escapes repository: {path}"
        ) from exc

    if not resolved.is_file():
        raise PackageInstallationValidationError(
            f"Required file is not regular: {path}"
        )

    return resolved


def validate_request(
    request: PackageInstallationRequest,
) -> Path:
    if not isinstance(request, PackageInstallationRequest):
        raise PackageInstallationValidationError(
            "Invalid package installation request"
        )

    manager = _validate_manager(request.manager)
    _validate_timeout(request.timeout)

    root = _resolve_root(request.repository_root)

    _regular_file(root, MANIFESTS[manager])
    _regular_file(root, LOCKFILES[manager])

    return root


def build_installation_command(
    manager: str,
) -> tuple[str, ...]:
    manager = _validate_manager(manager)

    if manager == "npm":
        return (
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        )

    raise PackageInstallationValidationError(
        f"No installation command for manager: {manager}"
    )


def _safe_environment(
    request: PackageInstallationRequest,
) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CI": "true",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    forbidden = {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
    }

    if request.environment:
        for key, value in request.environment.items():
            if not isinstance(key, str):
                raise PackageInstallationValidationError(
                    "Environment variable name must be a string"
                )

            if not isinstance(value, str):
                raise PackageInstallationValidationError(
                    "Environment variable value must be a string"
                )

            if key in forbidden:
                raise PackageInstallationValidationError(
                    f"Forbidden environment variable: {key}"
                )

            environment[key] = value

    return environment


def _load_package_json(root: Path) -> dict:
    manifest = _regular_file(root, "package.json")

    try:
        data = json.loads(
            manifest.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageInstallationValidationError(
            "Unable to parse package.json"
        ) from exc

    if not isinstance(data, dict):
        raise PackageInstallationValidationError(
            "package.json must contain a JSON object"
        )

    return data


def _expected_dependencies(root: Path) -> set[str]:
    manifest = _load_package_json(root)

    result: set[str] = set()

    for field in (
        "dependencies",
        "optionalDependencies",
    ):
        value = manifest.get(field, {})

        if not isinstance(value, dict):
            raise PackageInstallationValidationError(
                f"{field} must be an object"
            )

        result.update(
            str(name)
            for name in value
            if isinstance(name, str)
        )

    return result


def _validate_installation_directory(
    root: Path,
) -> Path:
    node_modules = root / "node_modules"

    if node_modules.is_symlink():
        raise PackageInstallationValidationError(
            "node_modules must not be a symlink"
        )

    try:
        resolved = node_modules.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PackageInstallationValidationError(
            "node_modules does not exist"
        ) from exc

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PackageInstallationValidationError(
            "node_modules escapes repository"
        ) from exc

    if not resolved.is_dir():
        raise PackageInstallationValidationError(
            "node_modules is not a directory"
        )

    return resolved


def _read_installed_packages(
    root: Path,
    expected_names: set[str],
) -> tuple[InstalledPackage, ...]:
    node_modules = _validate_installation_directory(root)

    installed: list[InstalledPackage] = []

    for name in sorted(expected_names):
        package_path = node_modules / name

        if package_path.is_symlink():
            raise PackageInstallationValidationError(
                f"Installed package is a symlink: {name}"
            )

        try:
            resolved = package_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PackageInstallationValidationError(
                f"Expected package is missing: {name}"
            ) from exc

        try:
            resolved.relative_to(node_modules)
        except ValueError as exc:
            raise PackageInstallationValidationError(
                f"Installed package escapes node_modules: {name}"
            ) from exc

        package_json = resolved / "package.json"

        if not package_json.is_file():
            raise PackageInstallationValidationError(
                f"Installed package metadata missing: {name}"
            )

        try:
            metadata = json.loads(
                package_json.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PackageInstallationValidationError(
                f"Invalid package metadata: {name}"
            ) from exc

        if not isinstance(metadata, dict):
            raise PackageInstallationValidationError(
                f"Invalid package metadata object: {name}"
            )

        actual_name = metadata.get("name")
        version = metadata.get("version")

        if actual_name != name:
            raise PackageInstallationValidationError(
                f"Package name mismatch: expected {name}, "
                f"got {actual_name!r}"
            )

        if not isinstance(version, str) or not version:
            raise PackageInstallationValidationError(
                f"Invalid installed version: {name}"
            )

        installed.append(
            InstalledPackage(
                name=name,
                version=version,
                path=resolved,
            )
        )

    return tuple(installed)


def _npm_ls(
    root: Path,
    timeout: float,
) -> tuple[int, str, str, bool]:
    command = (
        "npm",
        "ls",
        "--all",
        "--json",
        "--package-lock-only",
    )

    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "CI": "true",
                "NPM_CONFIG_AUDIT": "false",
                "NPM_CONFIG_FUND": "false",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            close_fds=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
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
        return -1, stdout, stderr, True
    except OSError as exc:
        return -1, "", str(exc), False

    return (
        completed.returncode,
        completed.stdout,
        completed.stderr,
        False,
    )


def validate_installed_state(
    root: Path,
) -> PackageInstallationResult:
    expected = _expected_dependencies(root)

    try:
        installed = _read_installed_packages(
            root,
            expected,
        )
    except PackageInstallationValidationError as exc:
        return PackageInstallationResult(
            success=False,
            manager="npm",
            command=build_installation_command("npm"),
            returncode=None,
            installed=(),
            expected_dependency_count=len(expected),
            actual_dependency_count=0,
            lockfile_present=(root / "package-lock.json").is_file(),
            installation_directory_present=(
                (root / "node_modules").is_dir()
            ),
            stdout="",
            stderr="",
            timed_out=False,
            error=str(exc),
        )

    return PackageInstallationResult(
        success=True,
        manager="npm",
        command=build_installation_command("npm"),
        returncode=0,
        installed=installed,
        expected_dependency_count=len(expected),
        actual_dependency_count=len(installed),
        lockfile_present=(root / "package-lock.json").is_file(),
        installation_directory_present=True,
        stdout="",
        stderr="",
        timed_out=False,
        error=None,
    )


def validate_installation_result(
    result: PackageInstallationResult,
) -> bool:
    if not isinstance(result, PackageInstallationResult):
        return False

    if result.manager not in SUPPORTED_MANAGERS:
        return False

    if result.success:
        if result.returncode != 0:
            return False

        if result.timed_out:
            return False

        if result.error is not None:
            return False

        if not result.lockfile_present:
            return False

        if not result.installation_directory_present:
            return False

        if result.actual_dependency_count != (
            result.expected_dependency_count
        ):
            return False

        if len(result.installed) != result.actual_dependency_count:
            return False

    return True


def install_and_validate(
    request: PackageInstallationRequest,
) -> PackageInstallationResult:
    root = validate_request(request)
    manager = _validate_manager(request.manager)
    command = build_installation_command(manager)
    environment = _safe_environment(request)

    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
            close_fds=True,
            timeout=request.timeout,
        )
    except subprocess.TimeoutExpired as exc:
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

        return PackageInstallationResult(
            success=False,
            manager=manager,
            command=command,
            returncode=None,
            installed=(),
            expected_dependency_count=0,
            actual_dependency_count=0,
            lockfile_present=(
                root / LOCKFILES[manager]
            ).is_file(),
            installation_directory_present=False,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            error="PACKAGE_INSTALLATION_TIMEOUT",
        )
    except OSError as exc:
        return PackageInstallationResult(
            success=False,
            manager=manager,
            command=command,
            returncode=None,
            installed=(),
            expected_dependency_count=0,
            actual_dependency_count=0,
            lockfile_present=(
                root / LOCKFILES[manager]
            ).is_file(),
            installation_directory_present=False,
            stdout="",
            stderr=str(exc),
            timed_out=False,
            error="PACKAGE_INSTALLATION_EXECUTION_ERROR",
        )

    if completed.returncode != 0:
        return PackageInstallationResult(
            success=False,
            manager=manager,
            command=command,
            returncode=completed.returncode,
            installed=(),
            expected_dependency_count=0,
            actual_dependency_count=0,
            lockfile_present=(
                root / LOCKFILES[manager]
            ).is_file(),
            installation_directory_present=(
                (root / "node_modules").is_dir()
            ),
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            error="PACKAGE_INSTALLATION_FAILED",
        )

    result = validate_installed_state(root)

    return PackageInstallationResult(
        success=result.success,
        manager=manager,
        command=command,
        returncode=completed.returncode,
        installed=result.installed,
        expected_dependency_count=result.expected_dependency_count,
        actual_dependency_count=result.actual_dependency_count,
        lockfile_present=result.lockfile_present,
        installation_directory_present=(
            result.installation_directory_present
        ),
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        error=result.error,
    )


__all__ = [
    "PackageInstallationValidationError",
    "PackageInstallationRequest",
    "InstalledPackage",
    "PackageInstallationResult",
    "SUPPORTED_MANAGERS",
    "build_installation_command",
    "validate_request",
    "validate_installed_state",
    "validate_installation_result",
    "install_and_validate",
]
