from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FrameworkCompatibilityInput:
    package_name: Optional[str]
    candidate_version: str
    framework_name: str
    framework_version: str
    minimum_framework_version: Optional[str] = None
    maximum_framework_version: Optional[str] = None


@dataclass(frozen=True)
class FrameworkCompatibilityResult:
    package_name: Optional[str]
    candidate_version: str
    framework_name: str
    framework_version: str
    minimum_framework_version: Optional[str]
    maximum_framework_version: Optional[str]
    compatible: bool
    reason: str


def _parse_version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise TypeError("VERSION_MUST_BE_STRING")

    value = value.strip()

    if not value:
        raise ValueError("VERSION_IS_EMPTY")

    if value.startswith(("v", "V")):
        value = value[1:]

    value = value.split("-", 1)[0]
    value = value.split("+", 1)[0]

    parts = value.split(".")

    if not 1 <= len(parts) <= 3:
        raise ValueError("VERSION_MUST_HAVE_ONE_TO_THREE_COMPONENTS")

    if not all(part.isdigit() for part in parts):
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NUMERIC")

    numbers = [int(part) for part in parts]

    while len(numbers) < 3:
        numbers.append(0)

    return tuple(numbers)


def _validate_optional_version(
    value: Optional[str],
    field_name: str,
) -> Optional[str]:
    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError(f"{field_name}_MUST_BE_STRING_OR_NONE")

    normalized = value.strip()

    if not normalized:
        raise ValueError(f"{field_name}_IS_EMPTY")

    _parse_version(normalized)
    return normalized


def assess_framework_compatibility(
    package_name: Optional[str],
    candidate_version: str,
    framework_name: str,
    framework_version: str,
    minimum_framework_version: Optional[str] = None,
    maximum_framework_version: Optional[str] = None,
) -> FrameworkCompatibilityResult:
    if package_name is not None:
        if not isinstance(package_name, str):
            raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")
        package_name = package_name.strip()

    if not isinstance(candidate_version, str) or isinstance(
        candidate_version, bool
    ):
        raise TypeError("CANDIDATE_VERSION_MUST_BE_STRING")

    if not isinstance(framework_name, str):
        raise TypeError("FRAMEWORK_NAME_MUST_BE_STRING")

    if not isinstance(framework_version, str) or isinstance(
        framework_version, bool
    ):
        raise TypeError("FRAMEWORK_VERSION_MUST_BE_STRING")

    candidate_version = candidate_version.strip()
    framework_name = framework_name.strip()
    framework_version = framework_version.strip()

    if not framework_name:
        raise ValueError("FRAMEWORK_NAME_IS_EMPTY")

    candidate_version_tuple = _parse_version(candidate_version)
    framework_version_tuple = _parse_version(framework_version)

    minimum_framework_version = _validate_optional_version(
        minimum_framework_version,
        "MINIMUM_FRAMEWORK_VERSION",
    )

    maximum_framework_version = _validate_optional_version(
        maximum_framework_version,
        "MAXIMUM_FRAMEWORK_VERSION",
    )

    minimum_tuple = (
        _parse_version(minimum_framework_version)
        if minimum_framework_version is not None
        else None
    )

    maximum_tuple = (
        _parse_version(maximum_framework_version)
        if maximum_framework_version is not None
        else None
    )

    if (
        minimum_tuple is not None
        and maximum_tuple is not None
        and minimum_tuple > maximum_tuple
    ):
        raise ValueError("MINIMUM_FRAMEWORK_EXCEEDS_MAXIMUM_FRAMEWORK")

    # Candidate version must be a valid dependency version.
    # Parsing is intentionally performed even when no framework
    # constraint is present so malformed candidate versions are rejected.
    _ = candidate_version_tuple

    if minimum_tuple is not None and framework_version_tuple < minimum_tuple:
        return FrameworkCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            framework_name=framework_name,
            framework_version=framework_version,
            minimum_framework_version=minimum_framework_version,
            maximum_framework_version=maximum_framework_version,
            compatible=False,
            reason="FRAMEWORK_BELOW_MINIMUM",
        )

    if maximum_tuple is not None and framework_version_tuple > maximum_tuple:
        return FrameworkCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            framework_name=framework_name,
            framework_version=framework_version,
            minimum_framework_version=minimum_framework_version,
            maximum_framework_version=maximum_framework_version,
            compatible=False,
            reason="FRAMEWORK_ABOVE_MAXIMUM",
        )

    return FrameworkCompatibilityResult(
        package_name=package_name,
        candidate_version=candidate_version,
        framework_name=framework_name,
        framework_version=framework_version,
        minimum_framework_version=minimum_framework_version,
        maximum_framework_version=maximum_framework_version,
        compatible=True,
        reason="FRAMEWORK_COMPATIBLE",
    )


# Public aliases.
framework_compatibility_assessment = assess_framework_compatibility
check_framework_compatibility = assess_framework_compatibility
is_framework_compatible = assess_framework_compatibility


__all__ = [
    "FrameworkCompatibilityInput",
    "FrameworkCompatibilityResult",
    "assess_framework_compatibility",
    "framework_compatibility_assessment",
    "check_framework_compatibility",
    "is_framework_compatible",
]
