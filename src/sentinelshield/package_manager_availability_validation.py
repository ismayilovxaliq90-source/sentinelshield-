from __future__ import annotations

from dataclasses import dataclass
import math
import shutil
import subprocess
from typing import Optional, Tuple


class PackageManagerAvailabilityValidationError(ValueError):
    """Raised when Task 179 input is invalid."""


SUPPORTED_PACKAGE_MANAGERS = frozenset(
    {
        "npm",
        "yarn",
        "pnpm",
        "pip",
        "poetry",
        "pipenv",
        "cargo",
        "go",
        "mvn",
        "gradle",
        "composer",
        "bundle",
        "dotnet",
    }
)


@dataclass(frozen=True)
class PackageManagerAvailabilityValidationInput:
    package_managers: Tuple[str, ...] = ("npm",)
    require_all: bool = True
    version_timeout_seconds: float = 10.0


@dataclass(frozen=True)
class PackageManagerAvailability:
    name: str
    available: bool
    executable: Optional[str]
    version: Optional[str]
    reason: str


@dataclass(frozen=True)
class PackageManagerAvailabilityValidationResult:
    valid: bool
    package_managers: Tuple[PackageManagerAvailability, ...]
    requested_count: int
    available_count: int
    missing_count: int
    failed_version_count: int
    require_all: bool
    reason: str


def _normalize_manager_name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(
            "PACKAGE_MANAGER_NAME_MUST_BE_STRING"
        )

    value = value.strip().casefold()

    if not value:
        raise PackageManagerAvailabilityValidationError(
            "PACKAGE_MANAGER_NAME_IS_EMPTY"
        )

    if value not in SUPPORTED_PACKAGE_MANAGERS:
        raise PackageManagerAvailabilityValidationError(
            f"UNSUPPORTED_PACKAGE_MANAGER:{value}"
        )

    return value


def _validate_input(
    request: PackageManagerAvailabilityValidationInput,
) -> PackageManagerAvailabilityValidationInput:
    if not isinstance(
        request,
        PackageManagerAvailabilityValidationInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_PACKAGE_MANAGER_AVAILABILITY_VALIDATION_INPUT"
        )

    if not isinstance(request.package_managers, tuple):
        raise TypeError(
            "PACKAGE_MANAGERS_MUST_BE_TUPLE"
        )

    if not request.package_managers:
        raise PackageManagerAvailabilityValidationError(
            "PACKAGE_MANAGER_LIST_IS_EMPTY"
        )

    normalized = tuple(
        _normalize_manager_name(item)
        for item in request.package_managers
    )

    if len(set(normalized)) != len(normalized):
        raise PackageManagerAvailabilityValidationError(
            "DUPLICATE_PACKAGE_MANAGER"
        )

    if not isinstance(request.require_all, bool):
        raise TypeError(
            "REQUIRE_ALL_MUST_BE_BOOLEAN"
        )

    if (
        isinstance(request.version_timeout_seconds, bool)
        or not isinstance(
            request.version_timeout_seconds,
            (int, float),
        )
        or not math.isfinite(
            float(request.version_timeout_seconds)
        )
        or request.version_timeout_seconds <= 0
    ):
        raise PackageManagerAvailabilityValidationError(
            "VERSION_TIMEOUT_MUST_BE_POSITIVE_FINITE_NUMBER"
        )

    return PackageManagerAvailabilityValidationInput(
        package_managers=normalized,
        require_all=request.require_all,
        version_timeout_seconds=float(
            request.version_timeout_seconds
        ),
    )


def _version_command(
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
        raise PackageManagerAvailabilityValidationError(
            "EXECUTABLE_NOT_FOUND"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise PackageManagerAvailabilityValidationError(
            "VERSION_COMMAND_TIMEOUT"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise PackageManagerAvailabilityValidationError(
            "VERSION_COMMAND_FAILED"
        ) from exc
    except OSError as exc:
        raise PackageManagerAvailabilityValidationError(
            "VERSION_COMMAND_OS_ERROR"
        ) from exc

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()

    # Some tools emit version information on stderr.
    output = stdout or stderr

    if not output:
        raise PackageManagerAvailabilityValidationError(
            "VERSION_OUTPUT_EMPTY"
        )

    return output.splitlines()[0].strip()


def _check_one(
    manager: str,
    timeout_seconds: float,
) -> PackageManagerAvailability:
    executable = shutil.which(manager)

    if executable is None:
        return PackageManagerAvailability(
            name=manager,
            available=False,
            executable=None,
            version=None,
            reason="PACKAGE_MANAGER_NOT_FOUND",
        )

    try:
        version = _version_command(
            executable,
            timeout_seconds,
        )
    except PackageManagerAvailabilityValidationError as exc:
        return PackageManagerAvailability(
            name=manager,
            available=False,
            executable=executable,
            version=None,
            reason=str(exc),
        )

    return PackageManagerAvailability(
        name=manager,
        available=True,
        executable=executable,
        version=version,
        reason="PACKAGE_MANAGER_AVAILABLE",
    )


def validate_package_manager_availability(
    request: PackageManagerAvailabilityValidationInput | None = None,
) -> PackageManagerAvailabilityValidationResult:
    if request is None:
        request = PackageManagerAvailabilityValidationInput()

    request = _validate_input(request)

    results = tuple(
        _check_one(
            manager,
            request.version_timeout_seconds,
        )
        for manager in request.package_managers
    )

    available_count = sum(
        item.available for item in results
    )

    missing_count = sum(
        item.reason == "PACKAGE_MANAGER_NOT_FOUND"
        for item in results
    )

    failed_version_count = sum(
        (
            not item.available
            and item.reason != "PACKAGE_MANAGER_NOT_FOUND"
        )
        for item in results
    )

    if request.require_all:
        valid = available_count == len(results)
    else:
        valid = available_count > 0

    if valid:
        reason = "ALL_REQUIRED_PACKAGE_MANAGERS_AVAILABLE"
    elif request.require_all and missing_count:
        reason = "REQUIRED_PACKAGE_MANAGER_MISSING"
    elif not request.require_all and available_count == 0:
        reason = "NO_REQUESTED_PACKAGE_MANAGER_AVAILABLE"
    else:
        reason = "PACKAGE_MANAGER_VALIDATION_FAILED"

    return PackageManagerAvailabilityValidationResult(
        valid=valid,
        package_managers=results,
        requested_count=len(results),
        available_count=available_count,
        missing_count=missing_count,
        failed_version_count=failed_version_count,
        require_all=request.require_all,
        reason=reason,
    )


# Public aliases
package_manager_availability_validation = (
    validate_package_manager_availability
)

check_package_manager_availability = (
    validate_package_manager_availability
)


def are_package_managers_available(
    request: PackageManagerAvailabilityValidationInput | None = None,
) -> bool:
    return validate_package_manager_availability(
        request
    ).valid
