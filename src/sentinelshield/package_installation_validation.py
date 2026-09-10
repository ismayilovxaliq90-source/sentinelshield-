from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class PackageInstallationValidationError(RuntimeError):
    """Raised when package-installation validation cannot be performed safely."""


SUPPORTED_MANAGERS = frozenset(
    {
        "npm",
        "pnpm",
        "yarn",
        "cargo",
        "go",
        "composer",
        "poetry",
    }
)


@dataclass(frozen=True)
class PackageInstallationRequest:
    workspace: Path
    manager: str
    timeout: float = 300.0
    environment: Mapping[str, str] | None = None


@dataclass(frozen=True)
class InstalledPackage:
    name: str
    version: str
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
        }


@dataclass(frozen=True)
class PackageInstallationResult:
    success: bool
    manager: str
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    installed_packages: tuple[InstalledPackage, ...]
    error: str | None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "manager": self.manager,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "installed_packages": [
                package.to_dict()
                for package in self.installed_packages
            ],
            "error": self.error,
        }


INSTALL_COMMANDS = {
    "npm": (
        "npm",
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    ),
    "pnpm": (
        "pnpm",
        "install",
        "--frozen-lockfile",
        "--ignore-scripts",
    ),
    "yarn": (
        "yarn",
        "install",
        "--ignore-scripts",
    ),
    "cargo": (
        "cargo",
        "fetch",
    ),
    "go": (
        "go",
        "mod",
        "download",
    ),
    "composer": (
        "composer",
        "install",
        "--no-interaction",
        "--no-scripts",
    ),
    "poetry": (
        "poetry",
        "install",
        "--no-root",
        "--no-interaction",
    ),
}


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


def build_install_command(manager: str) -> tuple[str, ...]:
    normalized = _validate_manager(manager)
    return INSTALL_COMMANDS[normalized]


def _resolve_workspace(workspace: Path) -> Path:
    if not isinstance(workspace, Path):
        raise PackageInstallationValidationError(
            "workspace must be a Path"
        )

    try:
        resolved = workspace.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PackageInstallationValidationError(
            f"Unable to resolve workspace: {workspace}"
        ) from exc

    if not resolved.is_dir():
        raise PackageInstallationValidationError(
            f"Workspace is not a directory: {resolved}"
        )

    if resolved.is_symlink():
        raise PackageInstallationValidationError(
            f"Symlink workspace is not allowed: {resolved}"
        )

    return resolved


def _find_repository_root(path: Path) -> Path | None:
    current = path

    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate

    return None


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
            "timeout must be greater than 0 and at most 1800 seconds"
        )


def validate_installation_request(
    request: PackageInstallationRequest,
) -> Path:
    if not isinstance(request, PackageInstallationRequest):
        raise PackageInstallationValidationError(
            "Invalid installation request"
        )

    manager = _validate_manager(request.manager)
    _validate_timeout(request.timeout)

    workspace = _resolve_workspace(request.workspace)

    repository_root = _find_repository_root(workspace)

    if repository_root is not None:
        if workspace == repository_root:
            raise PackageInstallationValidationError(
                "Installation cannot run directly in repository root"
            )

        try:
            workspace.relative_to(repository_root)
        except ValueError:
            pass
        else:
            raise PackageInstallationValidationError(
                "Installation workspace must not be inside repository"
            )

    if request.environment:
        forbidden = {
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "BASH_ENV",
            "ENV",
            "NODE_OPTIONS",
        }

        for key, value in request.environment.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise PackageInstallationValidationError(
                    "Environment keys and values must be strings"
                )

            if key in forbidden:
                raise PackageInstallationValidationError(
                    f"Forbidden environment variable: {key}"
                )

    if manager == "npm":
        package_json = workspace / "package.json"

        if not package_json.is_file():
            raise PackageInstallationValidationError(
                "npm workspace requires package.json"
            )

        if package_json.is_symlink():
            raise PackageInstallationValidationError(
                "package.json symlink is not allowed"
            )

    return workspace


def _build_environment(
    request: PackageInstallationRequest,
) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CI": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    forbidden = {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
    }

    if request.environment:
        for key, value in request.environment.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise PackageInstallationValidationError(
                    "Environment keys and values must be strings"
                )

            if key in forbidden:
                raise PackageInstallationValidationError(
                    f"Forbidden environment variable: {key}"
                )

            environment[key] = value

    return environment


def execute_package_installation(
    request: PackageInstallationRequest,
) -> PackageInstallationResult:
    workspace = validate_installation_request(request)
    manager = _validate_manager(request.manager)
    command = build_install_command(manager)
    environment = _build_environment(request)

    try:
        completed = subprocess.run(
            command,
            cwd=workspace,
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
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            installed_packages=(),
            error="PACKAGE_INSTALLATION_TIMEOUT",
        )

    except OSError as exc:
        return PackageInstallationResult(
            success=False,
            manager=manager,
            command=command,
            returncode=None,
            stdout="",
            stderr="",
            timed_out=False,
            installed_packages=(),
            error=f"PACKAGE_INSTALLATION_EXECUTION_ERROR: {exc}",
        )

    if completed.returncode != 0:
        return PackageInstallationResult(
            success=False,
            manager=manager,
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            installed_packages=(),
            error="PACKAGE_INSTALLATION_FAILED",
        )

    return PackageInstallationResult(
        success=True,
        manager=manager,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        installed_packages=(),
        error=None,
    )


def validate_package_installation_result(
    result: PackageInstallationResult,
) -> bool:
    if not isinstance(result, PackageInstallationResult):
        return False

    if result.manager not in SUPPORTED_MANAGERS:
        return False

    if result.timed_out:
        return False

    if result.success:
        if result.returncode != 0:
            return False

        if result.error is not None:
            return False

    return True


def validate_installed_package(
    package: InstalledPackage,
) -> bool:
    if not isinstance(package, InstalledPackage):
        return False

    if not package.name or not package.name.strip():
        return False

    if not package.version or not package.version.strip():
        return False

    return True


def attach_installed_packages(
    result: PackageInstallationResult,
    packages: tuple[InstalledPackage, ...],
) -> PackageInstallationResult:
    if not validate_package_installation_result(result):
        raise PackageInstallationValidationError(
            "Cannot attach packages to invalid result"
        )

    if not all(validate_installed_package(item) for item in packages):
        raise PackageInstallationValidationError(
            "Invalid installed package"
        )

    return PackageInstallationResult(
        success=result.success,
        manager=result.manager,
        command=result.command,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
        installed_packages=packages,
        error=result.error,
    )


__all__ = [
    "PackageInstallationValidationError",
    "PackageInstallationRequest",
    "InstalledPackage",
    "PackageInstallationResult",
    "SUPPORTED_MANAGERS",
    "build_install_command",
    "validate_installation_request",
    "execute_package_installation",
    "validate_package_installation_result",
    "validate_installed_package",
    "attach_installed_packages",
]
