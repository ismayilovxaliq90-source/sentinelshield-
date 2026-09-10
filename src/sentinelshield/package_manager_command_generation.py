from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional


class PackageManagerCommandGenerationError(ValueError):
    """Raised when a package-manager command cannot be safely generated."""


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
                "COMMAND_EXECUTION_NOT_ALLOWED"
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


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SHELL_META = re.compile(r"[;&|`$<>]")
_WHITESPACE = re.compile(r"\s")


def _validate_text(
    value: object,
    field: str,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_MUST_BE_STRING"
        )

    if not value.strip():
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_EMPTY"
        )

    if len(value) > maximum:
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_TOO_LONG"
        )

    if _CONTROL_CHARS.search(value):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_CONTROL_CHARACTER"
        )

    if _SHELL_META.search(value):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_SHELL_METACHARACTER"
        )

    if _WHITESPACE.search(value):
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_WHITESPACE_NOT_ALLOWED"
        )

    if ".." in value:
        raise PackageManagerCommandGenerationError(
            f"{field.upper()}_PATH_TRAVERSAL"
        )

    return value


def _normalize_ecosystem(value: object) -> str:
    if not isinstance(value, str):
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_MUST_BE_STRING"
        )

    value = value.strip().lower()

    if not value:
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_EMPTY"
        )

    if _CONTROL_CHARS.search(value):
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_CONTROL_CHARACTER"
        )

    if _SHELL_META.search(value):
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_SHELL_METACHARACTER"
        )

    if _WHITESPACE.search(value):
        raise PackageManagerCommandGenerationError(
            "ECOSYSTEM_WHITESPACE_NOT_ALLOWED"
        )

    return value


def _normalize_manager(value: object) -> str:
    if not isinstance(value, str):
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_MUST_BE_STRING"
        )

    value = value.strip().lower()

    if not value:
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_EMPTY"
        )

    if _CONTROL_CHARS.search(value):
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_CONTROL_CHARACTER"
        )

    if _SHELL_META.search(value):
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_SHELL_METACHARACTER"
        )

    if _WHITESPACE.search(value):
        raise PackageManagerCommandGenerationError(
            "PACKAGE_MANAGER_WHITESPACE_NOT_ALLOWED"
        )

    return value


def _validate_version(
    value: Optional[object],
    policy: PackageManagerCommandPolicy,
) -> Optional[str]:
    if value is None:
        return None

    version = _validate_text(
        value,
        "target_version",
        policy.max_version_length,
    )

    if not policy.allow_prerelease:
        lowered = version.lower()

        markers = (
            "alpha",
            "beta",
            "rc",
            "dev",
            "pre",
            "-a",
            "-b",
            "-rc",
        )

        if any(marker in lowered for marker in markers):
            raise PackageManagerCommandGenerationError(
                "PRERELEASE_VERSION_NOT_ALLOWED"
            )

    return version


def _build_command(
    ecosystem: str,
    manager: str,
    package: str,
    version: Optional[str],
) -> tuple[str, tuple[str, ...]]:
    if ecosystem == "python" and manager == "pip":
        if version is None:
            return (
                "python3",
                ("-m", "pip", "install", package),
            )

        return (
            "python3",
            (
                "-m",
                "pip",
                "install",
                f"{package}=={version}",
            ),
        )

    if ecosystem == "python" and manager == "poetry":
        if version is None:
            return (
                "poetry",
                ("add", package),
            )

        return (
            "poetry",
            ("add", f"{package}@{version}"),
        )

    if ecosystem == "python" and manager == "pipenv":
        if version is None:
            return (
                "pipenv",
                ("install", package),
            )

        return (
            "pipenv",
            ("install", f"{package}=={version}"),
        )

    if ecosystem == "node" and manager == "npm":
        if version is None:
            return (
                "npm",
                ("install", package),
            )

        return (
            "npm",
            ("install", f"{package}@{version}"),
        )

    if ecosystem == "node" and manager == "yarn":
        if version is None:
            return (
                "yarn",
                ("add", package),
            )

        return (
            "yarn",
            ("add", f"{package}@{version}"),
        )

    if ecosystem == "node" and manager == "pnpm":
        if version is None:
            return (
                "pnpm",
                ("add", package),
            )

        return (
            "pnpm",
            ("add", f"{package}@{version}"),
        )

    if ecosystem == "rust" and manager == "cargo":
        if version is None:
            raise PackageManagerCommandGenerationError(
                "CARGO_REQUIRES_TARGET_VERSION"
            )

        return (
            "cargo",
            (
                "update",
                "-p",
                package,
                "--precise",
                version,
            ),
        )

    if ecosystem == "php" and manager == "composer":
        if version is None:
            return (
                "composer",
                ("require", package),
            )

        return (
            "composer",
            (
                "require",
                f"{package}:{version}",
            ),
        )

    if ecosystem == "ruby" and manager in {
        "bundle",
        "bundler",
    }:
        if version is not None:
            raise PackageManagerCommandGenerationError(
                "BUNDLER_TARGET_VERSION_NOT_SUPPORTED"
            )

        return (
            "bundle",
            ("update", package),
        )

    if ecosystem == "dotnet" and manager == "dotnet":
        if version is None:
            return (
                "dotnet",
                ("add", "package", package),
            )

        return (
            "dotnet",
            (
                "add",
                "package",
                package,
                "--version",
                version,
            ),
        )

    if ecosystem == "java" and manager == "maven":
        if version is None:
            raise PackageManagerCommandGenerationError(
                "MAVEN_REQUIRES_TARGET_VERSION"
            )

        if ":" not in package:
            raise PackageManagerCommandGenerationError(
                "MAVEN_PACKAGE_MUST_BE_GROUP_ARTIFACT"
            )

        return (
            "mvn",
            (
                "versions:use-dep-version",
                f"-Dincludes={package}",
                f"-DdepVersion={version}",
                "-DforceVersion",
            ),
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

    if policy.max_package_length <= 0:
        raise PackageManagerCommandGenerationError(
            "INVALID_MAX_PACKAGE_LENGTH"
        )

    if policy.max_version_length <= 0:
        raise PackageManagerCommandGenerationError(
            "INVALID_MAX_VERSION_LENGTH"
        )

    ecosystem_value = _normalize_ecosystem(ecosystem)
    manager_value = _normalize_manager(package_manager)

    package_value = _validate_text(
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

    if not command:
        raise PackageManagerCommandGenerationError(
            "EMPTY_COMMAND"
        )

    for token in command:
        if not isinstance(token, str) or not token:
            raise PackageManagerCommandGenerationError(
                "INVALID_COMMAND_TOKEN"
            )

        if _CONTROL_CHARS.search(token):
            raise PackageManagerCommandGenerationError(
                "COMMAND_CONTROL_CHARACTER"
            )

        if _SHELL_META.search(token):
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
