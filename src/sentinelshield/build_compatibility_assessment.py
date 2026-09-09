from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class BuildCompatibilityInput:
    package_name: Optional[str]
    candidate_version: str
    build_system: str
    build_version: str
    minimum_build_version: Optional[str] = None
    maximum_build_version: Optional[str] = None


@dataclass(frozen=True)
class BuildCompatibilityResult:
    package_name: Optional[str]
    candidate_version: str
    build_system: str
    build_version: str
    minimum_build_version: Optional[str]
    maximum_build_version: Optional[str]
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

    value = value.strip()

    if not value:
        raise ValueError(f"{field_name}_IS_EMPTY")

    _parse_version(value)
    return value


def assess_build_compatibility(
    package_name: Optional[str],
    candidate_version: str,
    build_system: str,
    build_version: str,
    minimum_build_version: Optional[str] = None,
    maximum_build_version: Optional[str] = None,
) -> BuildCompatibilityResult:

    if package_name is not None:
        if not isinstance(package_name, str):
            raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")
        package_name = package_name.strip()

    if not isinstance(candidate_version, str):
        raise TypeError("CANDIDATE_VERSION_MUST_BE_STRING")

    if not isinstance(build_system, str):
        raise TypeError("BUILD_SYSTEM_MUST_BE_STRING")

    if not isinstance(build_version, str):
        raise TypeError("BUILD_VERSION_MUST_BE_STRING")

    candidate_version = candidate_version.strip()
    build_system = build_system.strip()
    build_version = build_version.strip()

    if not build_system:
        raise ValueError("BUILD_SYSTEM_IS_EMPTY")

    _parse_version(candidate_version)
    build_version_tuple = _parse_version(build_version)

    minimum_build_version = _validate_optional_version(
        minimum_build_version,
        "MINIMUM_BUILD_VERSION",
    )

    maximum_build_version = _validate_optional_version(
        maximum_build_version,
        "MAXIMUM_BUILD_VERSION",
    )

    minimum_tuple = (
        _parse_version(minimum_build_version)
        if minimum_build_version is not None
        else None
    )

    maximum_tuple = (
        _parse_version(maximum_build_version)
        if maximum_build_version is not None
        else None
    )

    if (
        minimum_tuple is not None
        and maximum_tuple is not None
        and minimum_tuple > maximum_tuple
    ):
        raise ValueError("MINIMUM_BUILD_EXCEEDS_MAXIMUM_BUILD")

    if (
        minimum_tuple is not None
        and build_version_tuple < minimum_tuple
    ):
        return BuildCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            build_system=build_system,
            build_version=build_version,
            minimum_build_version=minimum_build_version,
            maximum_build_version=maximum_build_version,
            compatible=False,
            reason="BUILD_BELOW_MINIMUM",
        )

    if (
        maximum_tuple is not None
        and build_version_tuple > maximum_tuple
    ):
        return BuildCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            build_system=build_system,
            build_version=build_version,
            minimum_build_version=minimum_build_version,
            maximum_build_version=maximum_build_version,
            compatible=False,
            reason="BUILD_ABOVE_MAXIMUM",
        )

    return BuildCompatibilityResult(
        package_name=package_name,
        candidate_version=candidate_version,
        build_system=build_system,
        build_version=build_version,
        minimum_build_version=minimum_build_version,
        maximum_build_version=maximum_build_version,
        compatible=True,
        reason="BUILD_COMPATIBLE",
    )


# Public aliases.
build_compatibility_assessment = assess_build_compatibility
check_build_compatibility = assess_build_compatibility
is_build_compatible = assess_build_compatibility


__all__ = [
    "BuildCompatibilityInput",
    "BuildCompatibilityResult",
    "assess_build_compatibility",
    "build_compatibility_assessment",
    "check_build_compatibility",
    "is_build_compatible",
]
