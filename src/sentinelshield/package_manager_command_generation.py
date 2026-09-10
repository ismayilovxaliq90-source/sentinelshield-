from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional


class PackageManagerCommandGenerationError(ValueError):
    """Raised when a safe package-manager command cannot be generated."""


@dataclass(frozen=True)
class PackageManagerCommandPolicy:
    max_package_length: int = 256
    max_version_length: int = 256
    allow_prerelease: bool = True


@dataclass(frozen=True)
class PackageManagerCommand:
    ecosystem: str
    package_manager: str
    package: str
    target_version: Optional[str]
    executable: str
    arguments: tuple[str, ...]
    command: tuple[str, ...]
    executed: bool = False

    def __post_init__(self) -> None:
        if self.command != (self.executable, *self.arguments):
            raise PackageManagerCommandGenerationError(
                "COMMAND_VECTOR_MISMATCH"
            )

        if self.executed:
            raise PackageManagerCommandGenerationError(
                "COMMAND_MUST_NOT_BE_EXECUTED"
            )

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "package_manager": self.package_manager,
            "package": self.package,
            "target_version": self.target_version,
            "executable": self.executable,
            "arguments": self.arguments,
            "command": self.command,
            "executed": self.executed,
        }


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SHELL_META_RE = re.compile(r"[;&|`$<>]")
_WHITESPACE_RE = re.compile(r"\s")


def _validate_token(
    value: object,
    field: str,
    max_length: int,
) -> str:
    if not isinstance(value, str):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_MUST_BE_STRING"
        )

    if not value or not value.strip():
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_EMPTY"
        )

    if len(value) > max_length:
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_TOO_LONG"
        )

    if _CONTROL_RE.search(value):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_CONTROL_CHARACTER"
        )

    if _SHELL_META_RE.search(value):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_SHELL_METACHARACTER"
        )

    if _WHITESPACE_RE.search(value):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_WHITESPACE_NOT_ALLOWED"
        )

    if ".." in value:
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_PATH_TRAVERSAL"
        )

    return value


def _normalize_manager(package_manager: object) -> str:
    if not isinstance(package_manager, str):
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_MUST_BE_STRING"
        )

    manager = package_manager.strip().lower()

    if not manager:
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_EMPTY"
        )

    if _CONTROL_RE.search(manager) or _SHELL_META_RE.search(manager):
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_UNSAFE"
        )

    if _WHITESPACE_RE.search(manager):
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_WHITESPACE_NOT_ALLOWED"
        )

    return manager


def _normalize_ecosystem(ecosystem: object) -> str:
    if not isinstance(ecosystem, str):
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_MUST_BE_STRING"
        )

    value = ecosystem.strip().lower()

    if not value:
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_EMPTY"
        )

    if _CONTROL_RE.search(value) or _SHELL_META_RE.search(value):
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_UNSAFE"
        )

    if _WHITESPACE_RE.search(value):
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_WHITESPACE_NOT_ALLOWED"
        )

    return value


def _validate_version(
    version: Optional[object],
    policy: PackageManagerCommandPolicy,
) -> Optional[str]:
    if version is None:
        return None

    value = _validate_token(
        version,
        "target_version",
        policy.max_version_length,
    )

    if not policy.allow_prerelease:
        lowered = value.lower()
        prerelease_markers = (
            "alpha",
            "beta",
            "rc",
            "dev",
            "pre",
            "-a",
            "-b",
            "-rc",
        )

        if any(marker in lowered for marker in prerelease_markers):
            raise PackageManagerCommandGenerationError(
                "PRERELEASE_VERSION_NOT_ALLOWED"
            )

    return value


def _build_command(
    ecosystem: str,
    manager: str,
    package: str,
    version: Optional[str],
) -> tuple[str, tuple[str, ...]]:
    target = None if version is None else version

    if ecosystem == "python" and manager == "pip":
        executable = "python3"
        if target is None:
            args = ("-m", "pip", "install", package)
        else:
            args = ("-m", "pip", "install", f"{package}=={target}")
        return executable, args

    if ecosystem == "python" and manager == "poetry":
        executable = "poetry"
        if target is None:
            args = ("add", package)
        else:
            args = ("add", f"{package}@{target}")
        return executable, args

    if ecosystem == "python" and manager == "pipenv":
        executable = "pipenv"
        if target is None:
            args = ("install", package)
        else:
            args = ("install", f"{package}=={target}")
        return executable, args

    if ecosystem == "node" and manager == "npm":
        executable = "npm"
        if target is None:
            args = ("install", package)
        else:
            args = ("install", f"{package}@{target}")
        return executable, args

    if ecosystem == "node" and manager == "yarn":
        executable = "yarn"
        if target is None:
            args = ("add", package)
        else:
            args = ("add", f"{package}@{target}")
        return executable, args

    if ecosystem == "node" and manager == "pnpm":
        executable = "pnpm"
        if target is None:
            args = ("add", package)
        else:
            args = ("add", f"{package}@{target}")
        return executable, args

    if ecosystem == "rust" and manager == "cargo":
        if target is None:
            raise PackageManagerCommandGenerationError(
                "CARGO_REQUIRES_TARGET_VERSION"
            )

        return "cargo", (
            "update",
            "-p",
            package,
            "--precise",
            target,
        )

    if ecosystem == "php" and manager == "composer":
        if target is None:
            return "composer", ("require", package)

        return "composer", (
            "require",
            f"{package}:{target}",
        )

    if ecosystem == "ruby" and manager in {"bundle", "bundler"}:
        if target is not None:
            raise PackageManagerCommandGenerationError(
                "BUNDLER_TARGET_VERSION_NOT_SUPPORTED"
            )

        return "bundle", ("update", package)

    if ecosystem == "dotnet" and manager == "dotnet":
        if target is None:
            return "dotnet", ("add", "package", package)

        return "dotnet", (
            "add",
            "package",
            package,
            "--version",
            target,
        )

    if ecosystem == "java" and manager == "maven":
        if target is None:
            raise PackageManagerCommandGenerationError(
                "MAVEN_REQUIRES_TARGET_VERSION"
            )

        if ":" not in package:
            raise PackageManagerCommandGenerationError(
                "MAVEN_PACKAGE_MUST_BE_GROUP_ARTIFACT"
            )

        return "mvn", (
            "versions:use-dep-version",
            f"-Dincludes={package}",
            f"-DdepVersion={target}",
            "-DforceVersion",
        )

    raise PackageManagerCommandGenerationError(
        "UNSUPPORTED_PACKAGE_MANAGER"
    )


def generate_package_manager_command(
    ecosystem: object,
    package_manager: object,
    package: object,
    target_version: Optional[object] = None,
    *,
    policy: Optional[PackageManagerCommandPolicy] = None,
) -> PackageManagerCommand:
    policy = policy or PackageManagerCommandPolicy()

    ecosystem_value = _normalize_ecosystem(ecosystem)
    manager_value = _normalize_manager(package_manager)

    package_value = _validate_token(
        package,
        "package",
        policy.max_package_length,
    )

    version_value = _validate_version(
        target_version,
        policy,
    )

    executable, arguments = _build_command(
        ecosystem_value,
        manager_value,
        package_value,
        version_value,
    )

    command = (executable, *arguments)

    for token in command:
        if not isinstance(token, str):
            raise PackageManagerCommandGenerationError(
                "COMMAND_TOKEN_MUST_BE_STRING"
            )

        if _CONTROL_RE.search(token):
            raise PackageManagerCommandGenerationError(
                "COMMAND_CONTROL_CHARACTER"
            )

        if _SHELL_META_RE.search(token):
            raise PackageManagerCommandGenerationError(
                "COMMAND_SHELL_METACHARACTER"
            )

        if "\n" in token or "\r" in token:
            raise PackageManagerCommandGenerationError(
                "COMMAND_NEWLINE"
            )

    return PackageManagerCommand(
        ecosystem=ecosystem_value,
        package_manager=manager_value,
        package=package_value,
        target_version=version_value,
        executable=executable,
        arguments=arguments,
        command=command,
        executed=False,
    )


def require_package_manager_command(
    ecosystem: object,
    package_manager: object,
    package: object,
    target_version: Optional[object] = None,
    *,
    policy: Optional[PackageManagerCommandPolicy] = None,
) -> PackageManagerCommand:
    return generate_package_manager_command(
        ecosystem,
        package_manager,
        package,
        target_version,
        policy=policy,
    )
