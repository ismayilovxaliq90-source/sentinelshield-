from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class PackageInstallationValidationError(RuntimeError):
    """Raised when package installation validation is unsafe or invalid."""


SUPPORTED_MANAGERS = frozenset({"npm"})

MANIFEST_NAME = "package.json"
LOCKFILE_NAME = "package-lock.json"
INSTALLATION_DIR = "node_modules"

DEFAULT_TIMEOUT = 300.0
MAX_TIMEOUT = 1800.0


@dataclass(frozen=True)
class InstalledPackage:
    name: str
    version: str
    path: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "path": str(self.path),
        }


@dataclass(frozen=True)
class PackageInstallationRequest:
    repository_root: Path
    manager: str = "npm"
    timeout: float = DEFAULT_TIMEOUT
    environment: Mapping[str, str] | None = None


@dataclass(frozen=True)
class PackageInstallationResult:
    success: bool
    manager: str
    command: tuple[str, ...]
    returncode: int | None
    expected_packages: tuple[str, ...]
    installed_packages: tuple[InstalledPackage, ...]
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
            "expected_packages": list(self.expected_packages),
            "installed_packages": [
                package.to_dict()
                for package in self.installed_packages
            ],
            "lockfile_present": self.lockfile_present,
            "installation_directory_present": (
                self.installation_directory_present
            ),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "error": self.error,
        }


def _resolve_root(repository_root: Path) -> Path:
    if not isinstance(repository_root, Path):
        raise PackageInstallationValidationError(
            "repository_root must be a pathlib.Path"
        )

    try:
        root = repository_root.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PackageInstallationValidationError(
            f"Unable to resolve repository root: {repository_root}"
        ) from exc

    if not root.is_dir():
        raise PackageInstallationValidationError(
            f"Repository root is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise PackageInstallationValidationError(
            f"Repository is not a Git repository: {root}"
        )

    return root


def _normalize_manager(manager: str) -> str:
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
            "timeout must not be boolean"
        )

    if not isinstance(timeout, (int, float)):
        raise PackageInstallationValidationError(
            "timeout must be numeric"
        )

    if timeout <= 0 or timeout > MAX_TIMEOUT:
        raise PackageInstallationValidationError(
            f"timeout must be between 0 and {MAX_TIMEOUT} seconds"
        )


def _regular_file(root: Path, relative_name: str) -> Path:
    path = root / relative_name

    if path.is_symlink():
        raise PackageInstallationValidationError(
            f"Symlink is not allowed: {path}"
        )

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PackageInstallationValidationError(
            f"Unable to resolve file: {path}"
        ) from exc

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PackageInstallationValidationError(
            f"Path escapes repository: {path}"
        ) from exc

    if not resolved.is_file():
        raise PackageInstallationValidationError(
            f"Not a regular file: {path}"
        )

    return resolved


def validate_request(
    request: PackageInstallationRequest,
) -> Path:
    if not isinstance(request, PackageInstallationRequest):
        raise PackageInstallationValidationError(
            "Invalid installation request"
        )

    manager = _normalize_manager(request.manager)
    _validate_timeout(request.timeout)

    root = _resolve_root(request.repository_root)

    if manager == "npm":
        _regular_file(root, MANIFEST_NAME)
        _regular_file(root, LOCKFILE_NAME)

    return root


def build_installation_command(
    manager: str,
) -> tuple[str, ...]:
    manager = _normalize_manager(manager)

    if manager == "npm":
        return (
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        )

    raise PackageInstallationValidationError(
        f"Installation command unavailable for: {manager}"
    )


def _build_environment(
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

    if request.environment is not None:
        for key, value in request.environment.items():
            if not isinstance(key, str):
                raise PackageInstallationValidationError(
                    "Environment key must be a string"
                )

            if not isinstance(value, str):
                raise PackageInstallationValidationError(
                    "Environment value must be a string"
                )

            if key in forbidden:
                raise PackageInstallationValidationError(
                    f"Forbidden environment variable: {key}"
                )

            environment[key] = value

    return environment


def _load_manifest(root: Path) -> dict:
    manifest = _regular_file(root, MANIFEST_NAME)

    try:
        data = json.loads(
            manifest.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageInstallationValidationError(
            "Invalid package.json"
        ) from exc

    if not isinstance(data, dict):
        raise PackageInstallationValidationError(
            "package.json must contain a JSON object"
        )

    return data


def expected_dependency_names(root: Path) -> tuple[str, ...]:
    manifest = _load_manifest(root)

    names: set[str] = set()

    for field in (
        "dependencies",
        "optionalDependencies",
    ):
        value = manifest.get(field, {})

        if not isinstance(value, dict):
            raise PackageInstallationValidationError(
                f"{field} must be a JSON object"
            )

        for name in value:
            if not isinstance(name, str) or not name.strip():
                raise PackageInstallationValidationError(
                    f"Invalid dependency name in {field}"
                )

            names.add(name)

    return tuple(sorted(names))


def _validate_node_modules(root: Path) -> Path:
    node_modules = root / INSTALLATION_DIR

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
            "node_modules escapes repository root"
        ) from exc

    if not resolved.is_dir():
        raise PackageInstallationValidationError(
            "node_modules is not a directory"
        )

    return resolved


def _read_package_metadata(
    package_directory: Path,
) -> tuple[str, str]:
    metadata_file = package_directory / "package.json"

    if metadata_file.is_symlink():
        raise PackageInstallationValidationError(
            f"Package metadata is a symlink: {metadata_file}"
        )

    if not metadata_file.is_file():
        raise PackageInstallationValidationError(
            f"Package metadata missing: {metadata_file}"
        )

    try:
        metadata = json.loads(
            metadata_file.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageInstallationValidationError(
            f"Invalid package metadata: {metadata_file}"
        ) from exc

    if not isinstance(metadata, dict):
        raise PackageInstallationValidationError(
            f"Invalid package metadata object: {metadata_file}"
        )

    name = metadata.get("name")
    version = metadata.get("version")

    if not isinstance(name, str) or not name:
        raise PackageInstallationValidationError(
            f"Invalid package name: {metadata_file}"
        )

    if not isinstance(version, str) or not version:
        raise PackageInstallationValidationError(
            f"Invalid package version: {metadata_file}"
        )

    return name, version


def _package_directory(
    node_modules: Path,
    package_name: str,
) -> Path:
    if package_name.startswith("@"):
        parts = package_name.split("/", 1)

        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise PackageInstallationValidationError(
                f"Invalid scoped package name: {package_name}"
            )

        return node_modules / parts[0] / parts[1]

    if "/" in package_name or "\\" in package_name:
        raise PackageInstallationValidationError(
            f"Invalid package name: {package_name}"
        )

    return node_modules / package_name


def discover_installed_packages(
    root: Path,
    expected: tuple[str, ...] | None = None,
) -> tuple[InstalledPackage, ...]:
    node_modules = _validate_node_modules(root)

    if expected is None:
        expected = expected_dependency_names(root)

    installed: list[InstalledPackage] = []

    for name in expected:
        package_directory = _package_directory(
            node_modules,
            name,
        )

        if package_directory.is_symlink():
            raise PackageInstallationValidationError(
                f"Installed package is a symlink: {name}"
            )

        try:
            resolved = package_directory.resolve(strict=True)
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

        if not resolved.is_dir():
            raise PackageInstallationValidationError(
                f"Installed package is not a directory: {name}"
            )

        actual_name, version = _read_package_metadata(
            resolved
        )

        if actual_name != name:
            raise PackageInstallationValidationError(
                f"Package name mismatch: expected {name}, "
                f"got {actual_name}"
            )

        installed.append(
            InstalledPackage(
                name=name,
                version=version,
                path=resolved,
            )
        )

    return tuple(installed)


def validate_installed_state(
    root: Path,
) -> PackageInstallationResult:
    manager = "npm"
    command = build_installation_command(manager)

    try:
        root = _resolve_root(root)

        expected = expected_dependency_names(root)

        _regular_file(root, LOCKFILE_NAME)

        installed = discover_installed_packages(
            root,
            expected,
        )

        if len(installed) != len(expected):
            return PackageInstallationResult(
                success=False,
                manager=manager,
                command=command,
                returncode=0,
                expected_packages=expected,
                installed_packages=installed,
                lockfile_present=True,
                installation_directory_present=True,
                stdout="",
                stderr="",
                timed_out=False,
                error="INSTALLED_DEPENDENCY_COUNT_MISMATCH",
            )

        return PackageInstallationResult(
            success=True,
            manager=manager,
            command=command,
            returncode=0,
            expected_packages=expected,
            installed_packages=installed,
            lockfile_present=True,
            installation_directory_present=True,
            stdout="",
            stderr="",
            timed_out=False,
            error=None,
        )

    except PackageInstallationValidationError as exc:
        return PackageInstallationResult(
            success=False,
            manager=manager,
            command=command,
            returncode=None,
            expected_packages=(),
            installed_packages=(),
            lockfile_present=(
                (root / LOCKFILE_NAME).is_file()
                if isinstance(root, Path)
                else False
            ),
            installation_directory_present=(
                (root / INSTALLATION_DIR).is_dir()
                if isinstance(root, Path)
                else False
            ),
            stdout="",
            stderr="",
            timed_out=False,
            error=str(exc),
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

        if len(result.expected_packages) != (
            len(result.installed_packages)
        ):
            return False

        for package in result.installed_packages:
            if not package.name:
                return False
            if not package.version:
                return False
            if not isinstance(package.path, Path):
                return False

    return True


def install_and_validate(
    request: PackageInstallationRequest,
) -> PackageInstallationResult:
    root = validate_request(request)

    manager = _normalize_manager(request.manager)
    command = build_installation_command(manager)
    environment = _build_environment(request)

    expected = expected_dependency_names(root)

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
            expected_packages=expected,
            installed_packages=(),
            lockfile_present=(
                (root / LOCKFILE_NAME).is_file()
            ),
            installation_directory_present=(
                (root / INSTALLATION_DIR).is_dir()
            ),
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
            expected_packages=expected,
            installed_packages=(),
            lockfile_present=(
                (root / LOCKFILE_NAME).is_file()
            ),
            installation_directory_present=(
                (root / INSTALLATION_DIR).is_dir()
            ),
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
            expected_packages=expected,
            installed_packages=(),
            lockfile_present=(
                (root / LOCKFILE_NAME).is_file()
            ),
            installation_directory_present=(
                (root / INSTALLATION_DIR).is_dir()
            ),
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            error="PACKAGE_INSTALLATION_FAILED",
        )

    validation = validate_installed_state(root)

    return PackageInstallationResult(
        success=validation.success,
        manager=manager,
        command=command,
        returncode=completed.returncode,
        expected_packages=validation.expected_packages,
        installed_packages=validation.installed_packages,
        lockfile_present=validation.lockfile_present,
        installation_directory_present=(
            validation.installation_directory_present
        ),
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        error=validation.error,
    )


__all__ = [
    "PackageInstallationValidationError",
    "InstalledPackage",
    "PackageInstallationRequest",
    "PackageInstallationResult",
    "SUPPORTED_MANAGERS",
    "MANIFEST_NAME",
    "LOCKFILE_NAME",
    "INSTALLATION_DIR",
    "build_installation_command",
    "validate_request",
    "expected_dependency_names",
    "discover_installed_packages",
    "validate_installed_state",
    "validate_installation_result",
    "install_and_validate",
]
