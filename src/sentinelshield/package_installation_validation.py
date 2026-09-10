from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import json
import os
import subprocess
from typing import Mapping, Sequence


class PackageInstallationValidationError(Exception):
    """Raised when package-installation validation cannot be performed safely."""


SUPPORTED_MANAGERS = {
    "npm": ("npm",),
    "pnpm": ("pnpm",),
    "yarn": ("yarn",),
    "pip": ("python", "-m", "pip"),
    "poetry": ("poetry",),
    "cargo": ("cargo",),
    "go": ("go",),
    "composer": ("composer",),
}

INSTALL_COMMANDS = {
    "npm": ("npm", "install"),
    "pnpm": ("pnpm", "install"),
    "yarn": ("yarn", "install"),
    "pip": ("python", "-m", "pip", "install"),
    "poetry": ("poetry", "install"),
    "cargo": ("cargo", "build"),
    "go": ("go", "mod", "download"),
    "composer": ("composer", "install"),
}

FORBIDDEN_ENV_KEYS = {
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "POETRY_HTTP_BASIC_PASSWORD",
    "COMPOSER_AUTH",
}


@dataclass(frozen=True)
class PackageSpec:
    name: str
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("package name must be non-empty")
        if self.version is not None:
            if not isinstance(self.version, str) or not self.version.strip():
                raise ValueError("package version must be non-empty when supplied")

    def to_dict(self) -> dict[str, str | None]:
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True)
class InstallationFingerprint:
    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class PackageInstallationRequest:
    repository_root: Path
    package_manager: str
    expected_packages: tuple[PackageSpec, ...] = field(default_factory=tuple)
    timeout: float = 300.0
    environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise TypeError("repository_root must be pathlib.Path")

        if self.package_manager not in SUPPORTED_MANAGERS:
            raise ValueError(
                f"unsupported package manager: {self.package_manager}"
            )

        if self.timeout <= 0:
            raise ValueError("timeout must be positive")

        for package in self.expected_packages:
            if not isinstance(package, PackageSpec):
                raise TypeError("expected_packages must contain PackageSpec values")

        for key in self.environment:
            if key.upper() in FORBIDDEN_ENV_KEYS:
                raise ValueError(f"secret environment variable is forbidden: {key}")


@dataclass(frozen=True)
class PackageInstallationValidationResult:
    success: bool
    package_manager: str
    command: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    expected_packages: tuple[PackageSpec, ...]
    missing_packages: tuple[str, ...]
    unexpected_packages: tuple[str, ...]
    fingerprints: tuple[InstallationFingerprint, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "package_manager": self.package_manager,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "expected_packages": [
                package.to_dict() for package in self.expected_packages
            ],
            "missing_packages": list(self.missing_packages),
            "unexpected_packages": list(self.unexpected_packages),
            "fingerprints": [
                fingerprint.to_dict()
                for fingerprint in self.fingerprints
            ],
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def _repository_root(path: Path) -> Path:
    root = path.expanduser().resolve()

    if not root.exists():
        raise PackageInstallationValidationError(
            f"repository does not exist: {root}"
        )

    if not root.is_dir():
        raise PackageInstallationValidationError(
            f"repository is not a directory: {root}"
        )

    if not (root / ".git").exists():
        raise PackageInstallationValidationError(
            f"not a git repository: {root}"
        )

    return root


def _validate_command(
    package_manager: str,
    command: Sequence[str],
) -> tuple[str, ...]:
    expected_prefix = SUPPORTED_MANAGERS[package_manager]

    if isinstance(command, (str, bytes)):
        raise PackageInstallationValidationError(
            "command must be a sequence, not a string"
        )

    normalized = tuple(command)

    if not normalized:
        raise PackageInstallationValidationError("command is empty")

    if normalized[: len(expected_prefix)] != expected_prefix:
        raise PackageInstallationValidationError(
            "command does not match package-manager executable"
        )

    allowed = INSTALL_COMMANDS[package_manager]

    if normalized[: len(allowed)] != allowed:
        raise PackageInstallationValidationError(
            f"command is not allowlisted for {package_manager}"
        )

    dangerous_tokens = {
        "&&",
        "||",
        ";",
        "|",
        ">",
        ">>",
        "<",
        "`",
        "$(",
    }

    if any(
        any(token in argument for token in dangerous_tokens)
        for argument in normalized
    ):
        raise PackageInstallationValidationError(
            "shell metacharacter detected"
        )

    return normalized


def build_install_command(
    package_manager: str,
) -> tuple[str, ...]:
    if package_manager not in INSTALL_COMMANDS:
        raise PackageInstallationValidationError(
            f"unsupported package manager: {package_manager}"
        )

    return INSTALL_COMMANDS[package_manager]


def _safe_environment(
    custom_environment: Mapping[str, str],
) -> dict[str, str]:
    result: dict[str, str] = {}

    safe_keys = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "CI",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_NO_INPUT",
        "npm_config_audit",
        "npm_config_fund",
        "COREPACK_ENABLE_DOWNLOAD_PROMPT",
    }

    for key in safe_keys:
        value = os.environ.get(key)
        if value is not None:
            result[key] = value

    for key, value in custom_environment.items():
        if key.upper() in FORBIDDEN_ENV_KEYS:
            raise PackageInstallationValidationError(
                f"secret environment variable is forbidden: {key}"
            )
        result[key] = str(value)

    result["CI"] = "true"
    result["PIP_NO_INPUT"] = "1"
    result["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

    return result


def _fingerprint(path: Path) -> InstallationFingerprint:
    digest = hashlib.sha256()
    size = 0

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)

    return InstallationFingerprint(
        path=str(path),
        sha256=digest.hexdigest(),
        size=size,
    )


def validate_package_manager_available(
    package_manager: str,
    timeout: float = 10.0,
) -> bool:
    if package_manager not in SUPPORTED_MANAGERS:
        return False

    command = SUPPORTED_MANAGERS[package_manager]

    try:
        completed = subprocess.run(
            (*command, "--version"),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return completed.returncode == 0


def validate_installation_result(
    result: PackageInstallationValidationResult,
) -> bool:
    if not result.success:
        return False

    if result.exit_code != 0:
        return False

    if result.timed_out:
        return False

    if result.missing_packages:
        return False

    if result.unexpected_packages:
        return False

    return True


def validate_package_installation(
    request: PackageInstallationRequest,
) -> PackageInstallationValidationResult:
    root = _repository_root(request.repository_root)
    command = _validate_command(
        request.package_manager,
        build_install_command(request.package_manager),
    )

    environment = _safe_environment(request.environment)

    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=request.timeout,
            check=False,
            close_fds=True,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as error:
        return PackageInstallationValidationResult(
            success=False,
            package_manager=request.package_manager,
            command=command,
            exit_code=None,
            timed_out=True,
            stdout=error.stdout or "",
            stderr=error.stderr or "",
            expected_packages=request.expected_packages,
            missing_packages=tuple(
                package.name for package in request.expected_packages
            ),
            unexpected_packages=(),
            fingerprints=(),
            reason="INSTALLATION_TIMEOUT",
        )
    except OSError as error:
        return PackageInstallationValidationResult(
            success=False,
            package_manager=request.package_manager,
            command=command,
            exit_code=None,
            timed_out=False,
            stdout="",
            stderr=str(error),
            expected_packages=request.expected_packages,
            missing_packages=tuple(
                package.name for package in request.expected_packages
            ),
            unexpected_packages=(),
            fingerprints=(),
            reason="INSTALLATION_EXECUTION_ERROR",
        )

    fingerprints: list[InstallationFingerprint] = []

    for candidate in (
        root / "package-lock.json",
        root / "pnpm-lock.yaml",
        root / "yarn.lock",
        root / "Cargo.lock",
        root / "go.sum",
        root / "composer.lock",
        root / "poetry.lock",
    ):
        try:
            if candidate.is_file() and not candidate.is_symlink():
                fingerprints.append(_fingerprint(candidate))
        except OSError:
            continue

    success = completed.returncode == 0

    return PackageInstallationValidationResult(
        success=success,
        package_manager=request.package_manager,
        command=command,
        exit_code=completed.returncode,
        timed_out=False,
        stdout=completed.stdout,
        stderr=completed.stderr,
        expected_packages=request.expected_packages,
        missing_packages=(),
        unexpected_packages=(),
        fingerprints=tuple(fingerprints),
        reason=(
            "INSTALLATION_SUCCESS"
            if success
            else "INSTALLATION_COMMAND_FAILED"
        ),
    )
