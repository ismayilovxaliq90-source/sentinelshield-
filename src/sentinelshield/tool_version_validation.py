from __future__ import annotations

from dataclasses import dataclass
import math
import re
import shutil
import subprocess
from typing import Optional, Tuple


class ToolVersionValidationError(ValueError):
    """Raised when Task 180 input is invalid."""


_VERSION_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$"
)


@dataclass(frozen=True)
class ToolVersionRequirement:
    name: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    required: bool = True


@dataclass(frozen=True)
class ToolVersionValidationInput:
    requirements: Tuple[ToolVersionRequirement, ...]
    timeout_seconds: float = 10.0


@dataclass(frozen=True)
class ToolVersionResult:
    name: str
    available: bool
    executable: Optional[str]
    version: Optional[str]
    normalized_version: Optional[Tuple[int, int, int]]
    valid: bool
    reason: str


@dataclass(frozen=True)
class ToolVersionValidationResult:
    valid: bool
    tools: Tuple[ToolVersionResult, ...]
    requested_count: int
    available_count: int
    valid_count: int
    invalid_count: int
    missing_count: int
    reason: str


def _parse_version(
    value: str,
) -> Tuple[int, int, int]:
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
            "REQUIREMENT_MUST_BE_TOOL_VERSION_REQUIREMENT"
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
        requirement.min_version is not None
        and not isinstance(requirement.min_version, str)
    ):
        raise TypeError(
            "MIN_VERSION_MUST_BE_STRING_OR_NONE"
        )

    if (
        requirement.max_version is not None
        and not isinstance(requirement.max_version, str)
    ):
        raise TypeError(
            "MAX_VERSION_MUST_BE_STRING_OR_NONE"
        )

    if not isinstance(requirement.required, bool):
        raise TypeError(
            "REQUIRED_MUST_BE_BOOLEAN"
        )

    minimum = (
        _parse_version(requirement.min_version)
        if requirement.min_version is not None
        else None
    )

    maximum = (
        _parse_version(requirement.max_version)
        if requirement.max_version is not None
        else None
    )

    if (
        minimum is not None
        and maximum is not None
        and maximum < minimum
    ):
        raise ToolVersionValidationError(
            "MAX_VERSION_MUST_NOT_BE_LESS_THAN_MIN_VERSION"
        )

    return ToolVersionRequirement(
        name=name,
        min_version=requirement.min_version.strip()
        if requirement.min_version is not None
        else None,
        max_version=requirement.max_version.strip()
        if requirement.max_version is not None
        else None,
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

    if not isinstance(request.requirements, tuple):
        raise TypeError(
            "REQUIREMENTS_MUST_BE_TUPLE"
        )

    if not request.requirements:
        raise ToolVersionValidationError(
            "REQUIREMENTS_ARE_EMPTY"
        )

    normalized = tuple(
        _validate_requirement(item)
        for item in request.requirements
    )

    names = [item.name.casefold() for item in normalized]

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
        requirements=normalized,
        timeout_seconds=float(request.timeout_seconds),
    )


def _get_tool_version(
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

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()

    output = stdout or stderr

    if not output:
        raise ToolVersionValidationError(
            "VERSION_OUTPUT_EMPTY"
        )

    return output.splitlines()[0].strip()


def _validate_one(
    requirement: ToolVersionRequirement,
    timeout_seconds: float,
) -> ToolVersionResult:
    executable = shutil.which(requirement.name)

    if executable is None:
        return ToolVersionResult(
            name=requirement.name,
            available=False,
            executable=None,
            version=None,
            normalized_version=None,
            valid=not requirement.required,
            reason=(
                "OPTIONAL_TOOL_NOT_FOUND"
                if not requirement.required
                else "REQUIRED_TOOL_NOT_FOUND"
            ),
        )

    try:
        version = _get_tool_version(
            executable,
            timeout_seconds,
        )

        normalized = _parse_version(version)

    except ToolVersionValidationError as exc:
        return ToolVersionResult(
            name=requirement.name,
            available=True,
            executable=executable,
            version=None,
            normalized_version=None,
            valid=False,
            reason=str(exc),
        )

    minimum = (
        _parse_version(requirement.min_version)
        if requirement.min_version is not None
        else None
    )

    maximum = (
        _parse_version(requirement.max_version)
        if requirement.max_version is not None
        else None
    )

    if minimum is not None and normalized < minimum:
        return ToolVersionResult(
            name=requirement.name,
            available=True,
            executable=executable,
            version=version,
            normalized_version=normalized,
            valid=False,
            reason="VERSION_BELOW_MINIMUM",
        )

    if maximum is not None and normalized > maximum:
        return ToolVersionResult(
            name=requirement.name,
            available=True,
            executable=executable,
            version=version,
            normalized_version=normalized,
            valid=False,
            reason="VERSION_ABOVE_MAXIMUM",
        )

    return ToolVersionResult(
        name=requirement.name,
        available=True,
        executable=executable,
        version=version,
        normalized_version=normalized,
        valid=True,
        reason="TOOL_VERSION_VALID",
    )


def validate_tool_versions(
    request: ToolVersionValidationInput,
) -> ToolVersionValidationResult:
    request = _validate_input(request)

    results = tuple(
        _validate_one(
            requirement,
            request.timeout_seconds,
        )
        for requirement in request.requirements
    )

    available_count = sum(
        item.available
        for item in results
    )

    valid_count = sum(
        item.valid
        for item in results
    )

    invalid_count = sum(
        item.available and not item.valid
        for item in results
    )

    missing_count = sum(
        not item.available
        for item in results
    )

    valid = all(
        item.valid
        for item in results
    )

    if valid:
        reason = "ALL_TOOL_VERSIONS_VALID"
    elif missing_count:
        reason = "REQUIRED_TOOL_MISSING"
    elif invalid_count:
        reason = "TOOL_VERSION_VALIDATION_FAILED"
    else:
        reason = "TOOL_VERSION_VALIDATION_FAILED"

    return ToolVersionValidationResult(
        valid=valid,
        tools=results,
        requested_count=len(results),
        available_count=available_count,
        valid_count=valid_count,
        invalid_count=invalid_count,
        missing_count=missing_count,
        reason=reason,
    )


# Public aliases
tool_version_validation = validate_tool_versions
check_tool_versions = validate_tool_versions


def are_tool_versions_valid(
    request: ToolVersionValidationInput,
) -> bool:
    return validate_tool_versions(request).valid
