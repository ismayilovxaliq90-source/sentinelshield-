from __future__ import annotations

from dataclasses import dataclass
import math
import re
import shutil
import subprocess
from typing import Optional


_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$")


class NodeEnvironmentValidationError(ValueError):
    """Raised when Task 178 input is invalid."""


@dataclass(frozen=True)
class NodeEnvironmentValidationInput:
    min_node_major: int = 18
    max_node_major: Optional[int] = None
    require_npm: bool = True


@dataclass(frozen=True)
class NodeEnvironmentValidationResult:
    valid: bool
    node_available: bool
    node_version: Optional[str]
    node_major: Optional[int]
    npm_available: bool
    npm_version: Optional[str]
    platform: Optional[str]
    node_executable: Optional[str]
    npm_executable: Optional[str]
    reason: str


def _validate_input(
    value: NodeEnvironmentValidationInput,
) -> NodeEnvironmentValidationInput:
    if not isinstance(value, NodeEnvironmentValidationInput):
        raise TypeError("INPUT_MUST_BE_NODE_ENVIRONMENT_VALIDATION_INPUT")

    if (
        isinstance(value.min_node_major, bool)
        or not isinstance(value.min_node_major, int)
        or value.min_node_major < 0
    ):
        raise NodeEnvironmentValidationError(
            "MIN_NODE_MAJOR_MUST_BE_NON_NEGATIVE_INTEGER"
        )

    if value.max_node_major is not None:
        if (
            isinstance(value.max_node_major, bool)
            or not isinstance(value.max_node_major, int)
            or value.max_node_major < 0
        ):
            raise NodeEnvironmentValidationError(
                "MAX_NODE_MAJOR_MUST_BE_NON_NEGATIVE_INTEGER"
            )

        if value.max_node_major < value.min_node_major:
            raise NodeEnvironmentValidationError(
                "MAX_NODE_MAJOR_MUST_NOT_BE_LESS_THAN_MIN_NODE_MAJOR"
            )

    if not isinstance(value.require_npm, bool):
        raise TypeError("REQUIRE_NPM_MUST_BE_BOOLEAN")

    return value


def _parse_node_major(version: str) -> int:
    if not isinstance(version, str):
        raise NodeEnvironmentValidationError(
            "NODE_VERSION_MUST_BE_STRING"
        )

    value = version.strip()

    match = _VERSION_RE.fullmatch(value)
    if not match:
        raise NodeEnvironmentValidationError(
            "INVALID_NODE_VERSION"
        )

    major = int(match.group(1))

    return major


def _run_version_command(
    executable: str,
) -> str:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except FileNotFoundError as exc:
        raise NodeEnvironmentValidationError(
            "EXECUTABLE_NOT_FOUND"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise NodeEnvironmentValidationError(
            "VERSION_COMMAND_TIMEOUT"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise NodeEnvironmentValidationError(
            "VERSION_COMMAND_FAILED"
        ) from exc
    except OSError as exc:
        raise NodeEnvironmentValidationError(
            "VERSION_COMMAND_OS_ERROR"
        ) from exc

    output = completed.stdout.strip()

    if not output:
        raise NodeEnvironmentValidationError(
            "VERSION_OUTPUT_EMPTY"
        )

    return output


def validate_node_environment(
    request: NodeEnvironmentValidationInput | None = None,
) -> NodeEnvironmentValidationResult:
    if request is None:
        request = NodeEnvironmentValidationInput()

    request = _validate_input(request)

    node_executable = shutil.which("node")

    if not node_executable:
        return NodeEnvironmentValidationResult(
            valid=False,
            node_available=False,
            node_version=None,
            node_major=None,
            npm_available=False,
            npm_version=None,
            platform=None,
            node_executable=None,
            npm_executable=None,
            reason="NODE_NOT_FOUND",
        )

    try:
        node_version = _run_version_command(node_executable)
        node_major = _parse_node_major(node_version)
    except NodeEnvironmentValidationError as exc:
        return NodeEnvironmentValidationResult(
            valid=False,
            node_available=True,
            node_version=None,
            node_major=None,
            npm_available=False,
            npm_version=None,
            platform=None,
            node_executable=node_executable,
            npm_executable=None,
            reason=str(exc),
        )

    if node_major < request.min_node_major:
        return NodeEnvironmentValidationResult(
            valid=False,
            node_available=True,
            node_version=node_version,
            node_major=node_major,
            npm_available=False,
            npm_version=None,
            platform=None,
            node_executable=node_executable,
            npm_executable=None,
            reason="NODE_VERSION_BELOW_MINIMUM",
        )

    if (
        request.max_node_major is not None
        and node_major > request.max_node_major
    ):
        return NodeEnvironmentValidationResult(
            valid=False,
            node_available=True,
            node_version=node_version,
            node_major=node_major,
            npm_available=False,
            npm_version=None,
            platform=None,
            node_executable=node_executable,
            npm_executable=None,
            reason="NODE_VERSION_ABOVE_MAXIMUM",
        )

    npm_executable = shutil.which("npm")

    if request.require_npm and not npm_executable:
        return NodeEnvironmentValidationResult(
            valid=False,
            node_available=True,
            node_version=node_version,
            node_major=node_major,
            npm_available=False,
            npm_version=None,
            platform=None,
            node_executable=node_executable,
            npm_executable=None,
            reason="NPM_NOT_FOUND",
        )

    npm_version = None

    if npm_executable:
        try:
            npm_version = _run_version_command(npm_executable)
        except NodeEnvironmentValidationError as exc:
            return NodeEnvironmentValidationResult(
                valid=False,
                node_available=True,
                node_version=node_version,
                node_major=node_major,
                npm_available=True,
                npm_version=None,
                platform=None,
                node_executable=node_executable,
                npm_executable=npm_executable,
                reason=f"NPM_VALIDATION_FAILED:{exc}",
            )

    # platform məlumatı yalnız Server/CI icrasında alınır.
    import platform

    return NodeEnvironmentValidationResult(
        valid=True,
        node_available=True,
        node_version=node_version,
        node_major=node_major,
        npm_available=bool(npm_executable),
        npm_version=npm_version,
        platform=platform.platform(),
        node_executable=node_executable,
        npm_executable=npm_executable,
        reason="NODE_ENVIRONMENT_VALID",
    )


# Public aliases
node_environment_validation = validate_node_environment
check_node_environment = validate_node_environment
is_node_environment_valid = lambda request=None: (
    validate_node_environment(request).valid
)
