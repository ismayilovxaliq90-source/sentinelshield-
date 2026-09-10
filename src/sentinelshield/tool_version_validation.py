from __future__ import annotations

from dataclasses import dataclass
import math
import re
import shutil
import subprocess
from typing import Optional, Tuple


class ToolVersionValidationError(ValueError):
    """Invalid Task 180 input."""


@dataclass(frozen=True)
class ToolVersionRequirement:
    name: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    required: bool = True


@dataclass(frozen=True)
class ToolVersionResult:
    name: str
    required: bool
    available: bool
    executable: Optional[str]
    version: Optional[str]
    version_tuple: Optional[Tuple[int, int, int]]
    compatible: bool
    reason: str


@dataclass(frozen=True)
class ToolVersionValidationInput:
    tools: Tuple[ToolVersionRequirement, ...]
    timeout_seconds: float = 10.0


@dataclass(frozen=True)
class ToolVersionValidationResult:
    valid: bool
    tools: Tuple[ToolVersionResult, ...]
    total_count: int
    available_count: int
    compatible_count: int
    missing_count: int
    incompatible_count: int
    reason: str


_VERSION_RE = re.compile(
    r"^[vV]?(\d+)"
    r"(?:\.(\d+))?"
    r"(?:\.(\d+))?"
    r"(?:[-+].*)?$"
)


def _parse_version(value: str) -> Tuple[int, int, int]:
    if not isinstance(value, str):
        raise ToolVersionValidationError(
            "VERSION_MUST_BE_STRING"
        )

    value = value.strip()

    if not value:
        raise ToolVersionValidationError(
            "VERSION_IS_EMPTY"
        )

    match = _VERSION_RE.fullmatch(value)

    if not match:
        raise ToolVersionValidationError(
            "INVALID_VERSION_FORMAT"
        )

    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
    )


def _validate_requirement(
    requirement: ToolVersionRequirement,
) -> ToolVersionRequirement:
    if not isinstance(
        requirement,
        ToolVersionRequirement,
    ):
        raise TypeError(
            "TOOL_REQUIREMENT_MUST_BE_TOOL_VERSION_REQUIREMENT"
        )

    if not isinstance(requirement.name, str):
        raise TypeError(
            "TOOL_NAME_MUST_BE_STRING"
        )

    name = requirement.name.strip()

    if not name:
        raise ToolVersionValidationError(
            "TOOL_NAME_IS_EMPTY"
        )

    if (
        "/" in name
        or "\\" in name
        or any(
            character.isspace()
            for character in name
        )
    ):
        raise ToolVersionValidationError(
            "INVALID_TOOL_NAME"
        )

    if not isinstance(requirement.required, bool):
        raise TypeError(
            "REQUIRED_MUST_BE_BOOLEAN"
        )

    if requirement.min_version is not None:
        _parse_version(requirement.min_version)

    if requirement.max_version is not None:
        _parse_version(requirement.max_version)

    if (
        requirement.min_version is not None
        and requirement.max_version is not None
        and _parse_version(requirement.min_version)
        > _parse_version(requirement.max_version)
    ):
        raise ToolVersionValidationError(
            "MIN_VERSION_MUST_NOT_EXCEED_MAX_VERSION"
        )

    return ToolVersionRequirement(
        name=name,
        min_version=requirement.min_version,
        max_version=requirement.max_version,
        required=requirement.required,
    )


def _validate_input(
    request: ToolVersionValidationInput,
) -> ToolVersionValidationInput:
    if not isinstance(
        request,
        ToolVersionValidationInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_TOOL_VERSION_VALIDATION_INPUT"
        )

    if not isinstance(request.tools, tuple):
        raise TypeError(
            "TOOLS_MUST_BE_TUPLE"
        )

    if not request.tools:
        raise ToolVersionValidationError(
            "TOOL_REQUIREMENT_LIST_IS_EMPTY"
        )

    normalized = tuple(
        _validate_requirement(tool)
        for tool in request.tools
    )

    names = [tool.name.casefold() for tool in normalized]

    if len(names) != len(set(names)):
        raise ToolVersionValidationError(
            "DUPLICATE_TOOL_REQUIREMENT"
        )

    if (
        isinstance(request.timeout_seconds, bool)
        or not isinstance(
            request.timeout_seconds,
            (int, float),
        )
        or not math.isfinite(
            float(request.timeout_seconds)
        )
        or request.timeout_seconds <= 0
    ):
        raise ToolVersionValidationError(
            "TIMEOUT_MUST_BE_POSITIVE_FINITE_NUMBER"
        )

    return ToolVersionValidationInput(
        tools=normalized,
        timeout_seconds=float(
            request.timeout_seconds
        ),
    )


def _read_tool_version(
    executable: str,
    timeout_seconds: float,
) -> str:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise ToolVersionValidationError(
            "EXECUTABLE_NOT_FOUND"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolVersionValidationError(
            "VERSION_COMMAND_TIMEOUT"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise ToolVersionValidationError(
            "VERSION_COMMAND_FAILED"
        ) from exc
    except OSError as exc:
        raise ToolVersionValidationError(
            "VERSION_COMMAND_OS_ERROR"
        ) from exc

    output = (
        (completed.stdout or "").strip()
        or (completed.stderr or "").strip()
    )

    if not output:
        raise ToolVersionValidationError(
            "VERSION_OUTPUT_EMPTY"
        )

    # Use the first non-empty line because some tools
    # print additional diagnostic information.
    for line in output.splitlines():
        line = line.strip()
        if line:
            return line

    raise ToolVersionValidationError(
        "VERSION_OUTPUT_EMPTY"
    )


def _version_compatible(
    actual: Tuple[int, int, int],
    requirement: ToolVersionRequirement,
) -> bool:
    if requirement.min_version is not None:
        minimum = _parse_version(
            requirement.min_version
        )
        if actual < minimum:
            return False

    if requirement.max_version is not None:
        maximum = _parse_version(
            requirement.max_version
        )
        if actual > maximum:
            return False

    return True


def _check_tool(
    requirement: ToolVersionRequirement,
    timeout_seconds: float,
) -> ToolVersionResult:
    executable = shutil.which(requirement.name)

    if executable is None:
        return ToolVersionResult(
            name=requirement.name,
            required=requirement.required,
            available=False,
            executable=None,
            version=None,
            version_tuple=None,
            compatible=False,
            reason="TOOL_NOT_FOUND",
        )

    try:
        raw_version = _read_tool_version(
            executable,
            timeout_seconds,
        )

        # Version command output may contain a prefix such as
        # "git version 2.51.0". Extract the first semantic-looking
        # version safely.
        match = re.search(
            r"[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?",
            raw_version,
        )

        if not match:
            raise ToolVersionValidationError(
                "VERSION_NOT_DETECTABLE"
            )

        parsed = (
            int(match.group(1)),
            int(match.group(2) or 0),
            int(match.group(3) or 0),
        )

        compatible = _version_compatible(
            parsed,
            requirement,
        )

        return ToolVersionResult(
            name=requirement.name,
            required=requirement.required,
            available=True,
            executable=executable,
            version=raw_version,
            version_tuple=parsed,
            compatible=compatible,
            reason=(
                "TOOL_VERSION_COMPATIBLE"
                if compatible
                else "TOOL_VERSION_INCOMPATIBLE"
            ),
        )

    except ToolVersionValidationError as exc:
        return ToolVersionResult(
            name=requirement.name,
            required=requirement.required,
            available=True,
            executable=executable,
            version=None,
            version_tuple=None,
            compatible=False,
            reason=str(exc),
        )


def validate_tool_versions(
    request: ToolVersionValidationInput,
) -> ToolVersionValidationResult:
    request = _validate_input(request)

    results = tuple(
        _check_tool(
            tool,
            request.timeout_seconds,
        )
        for tool in request.tools
    )

    available_count = sum(
        item.available for item in results
    )

    compatible_count = sum(
        item.available and item.compatible
        for item in results
    )

    missing_count = sum(
        not item.available
        for item in results
    )

    incompatible_count = sum(
        item.available and not item.compatible
        for item in results
    )

    # Required tools must exist and have compatible versions.
    # Optional tools do not invalidate the complete result when
    # absent or incompatible.
    valid = all(
        (
            not item.required
            or (
                item.available
                and item.compatible
            )
        )
        for item in results
    )

    if valid:
        reason = "ALL_REQUIRED_TOOL_VERSIONS_VALID"
    else:
        reason = "REQUIRED_TOOL_VERSION_VALIDATION_FAILED"

    return ToolVersionValidationResult(
        valid=valid,
        tools=results,
        total_count=len(results),
        available_count=available_count,
        compatible_count=compatible_count,
        missing_count=missing_count,
        incompatible_count=incompatible_count,
        reason=reason,
    )


# Public aliases
tool_version_validation = validate_tool_versions
check_tool_versions = validate_tool_versions


def are_tool_versions_valid(
    request: ToolVersionValidationInput,
) -> bool:
    return validate_tool_versions(request).valid
