from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class APICompatibilityInput:
    package_name: Optional[str]
    candidate_version: str
    api_name: str
    api_version: str
    minimum_api_version: Optional[str] = None
    maximum_api_version: Optional[str] = None


@dataclass(frozen=True)
class APICompatibilityResult:
    package_name: Optional[str]
    candidate_version: str
    api_name: str
    api_version: str
    minimum_api_version: Optional[str]
    maximum_api_version: Optional[str]
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


def assess_api_compatibility(
    package_name: Optional[str],
    candidate_version: str,
    api_name: str,
    api_version: str,
    minimum_api_version: Optional[str] = None,
    maximum_api_version: Optional[str] = None,
) -> APICompatibilityResult:
    if package_name is not None:
        if not isinstance(package_name, str):
            raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")
        package_name = package_name.strip()

    if not isinstance(candidate_version, str):
        raise TypeError("CANDIDATE_VERSION_MUST_BE_STRING")

    if not isinstance(api_name, str):
        raise TypeError("API_NAME_MUST_BE_STRING")

    if not isinstance(api_version, str):
        raise TypeError("API_VERSION_MUST_BE_STRING")

    candidate_version = candidate_version.strip()
    api_name = api_name.strip()
    api_version = api_version.strip()

    if not api_name:
        raise ValueError("API_NAME_IS_EMPTY")

    # Validate candidate dependency version as part of the assessment.
    _parse_version(candidate_version)

    api_version_tuple = _parse_version(api_version)

    minimum_api_version = _validate_optional_version(
        minimum_api_version,
        "MINIMUM_API_VERSION",
    )

    maximum_api_version = _validate_optional_version(
        maximum_api_version,
        "MAXIMUM_API_VERSION",
    )

    minimum_tuple = (
        _parse_version(minimum_api_version)
        if minimum_api_version is not None
        else None
    )

    maximum_tuple = (
        _parse_version(maximum_api_version)
        if maximum_api_version is not None
        else None
    )

    if (
        minimum_tuple is not None
        and maximum_tuple is not None
        and minimum_tuple > maximum_tuple
    ):
        raise ValueError("MINIMUM_API_EXCEEDS_MAXIMUM_API")

    if minimum_tuple is not None and api_version_tuple < minimum_tuple:
        return APICompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            api_name=api_name,
            api_version=api_version,
            minimum_api_version=minimum_api_version,
            maximum_api_version=maximum_api_version,
            compatible=False,
            reason="API_BELOW_MINIMUM",
        )

    if maximum_tuple is not None and api_version_tuple > maximum_tuple:
        return APICompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            api_name=api_name,
            api_version=api_version,
            minimum_api_version=minimum_api_version,
            maximum_api_version=maximum_api_version,
            compatible=False,
            reason="API_ABOVE_MAXIMUM",
        )

    return APICompatibilityResult(
        package_name=package_name,
        candidate_version=candidate_version,
        api_name=api_name,
        api_version=api_version,
        minimum_api_version=minimum_api_version,
        maximum_api_version=maximum_api_version,
        compatible=True,
        reason="API_COMPATIBLE",
    )


# Public aliases.
api_compatibility_assessment = assess_api_compatibility
check_api_compatibility = assess_api_compatibility
is_api_compatible = assess_api_compatibility


__all__ = [
    "APICompatibilityInput",
    "APICompatibilityResult",
    "assess_api_compatibility",
    "api_compatibility_assessment",
    "check_api_compatibility",
    "is_api_compatible",
]
