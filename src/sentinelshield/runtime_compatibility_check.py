from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RuntimeCompatibilityResult:
    package_name: Optional[str]
    candidate_version: str
    runtime_version: str
    minimum_runtime_version: Optional[str]
    maximum_runtime_version: Optional[str]
    compatible: bool
    reason: str


@dataclass(frozen=True)
class RuntimeCompatibilityInput:
    package_name: Optional[str]
    candidate_version: str
    runtime_version: str
    minimum_runtime_version: Optional[str] = None
    maximum_runtime_version: Optional[str] = None


def _parse_version(version: object) -> tuple[int, int, int]:
    if not isinstance(version, str):
        raise TypeError("VERSION_MUST_BE_STRING")

    value = version.strip()

    if not value:
        raise ValueError("VERSION_IS_EMPTY")

    if value.startswith(("v", "V")):
        value = value[1:]

    value = value.split("-", 1)[0].split("+", 1)[0]
    parts = value.split(".")

    if len(parts) > 3 or len(parts) < 1:
        raise ValueError("VERSION_MUST_HAVE_ONE_TO_THREE_COMPONENTS")

    if not all(part.isdigit() for part in parts):
        raise ValueError("VERSION_COMPONENTS_MUST_BE_NUMERIC")

    numbers = [int(part) for part in parts]

    while len(numbers) < 3:
        numbers.append(0)

    return tuple(numbers)


def _normalize_optional_version(
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


def check_runtime_compatibility(
    package_name: Optional[str],
    candidate_version: str,
    runtime_version: str,
    minimum_runtime_version: Optional[str] = None,
    maximum_runtime_version: Optional[str] = None,
) -> RuntimeCompatibilityResult:
    if package_name is not None and not isinstance(package_name, str):
        raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")

    if package_name is not None:
        package_name = package_name.strip()

    if isinstance(candidate_version, bool) or not isinstance(
        candidate_version, str
    ):
        raise TypeError("CANDIDATE_VERSION_MUST_BE_STRING")

    if isinstance(runtime_version, bool) or not isinstance(
        runtime_version, str
    ):
        raise TypeError("RUNTIME_VERSION_MUST_BE_STRING")

    candidate_version = candidate_version.strip()
    runtime_version = runtime_version.strip()

    candidate_tuple = _parse_version(candidate_version)
    runtime_tuple = _parse_version(runtime_version)

    minimum_runtime_version = _normalize_optional_version(
        minimum_runtime_version,
        "MINIMUM_RUNTIME_VERSION",
    )

    maximum_runtime_version = _normalize_optional_version(
        maximum_runtime_version,
        "MAXIMUM_RUNTIME_VERSION",
    )

    if (
        minimum_runtime_version is not None
        and maximum_runtime_version is not None
    ):
        minimum_tuple = _parse_version(minimum_runtime_version)
        maximum_tuple = _parse_version(maximum_runtime_version)

        if minimum_tuple > maximum_tuple:
            raise ValueError("MINIMUM_RUNTIME_EXCEEDS_MAXIMUM_RUNTIME")

    if (
        minimum_runtime_version is not None
        and runtime_tuple < _parse_version(minimum_runtime_version)
    ):
        return RuntimeCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            runtime_version=runtime_version,
            minimum_runtime_version=minimum_runtime_version,
            maximum_runtime_version=maximum_runtime_version,
            compatible=False,
            reason="RUNTIME_BELOW_MINIMUM",
        )

    if (
        maximum_runtime_version is not None
        and runtime_tuple > _parse_version(maximum_runtime_version)
    ):
        return RuntimeCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            runtime_version=runtime_version,
            minimum_runtime_version=minimum_runtime_version,
            maximum_runtime_version=maximum_runtime_version,
            compatible=False,
            reason="RUNTIME_ABOVE_MAXIMUM",
        )

    return RuntimeCompatibilityResult(
        package_name=package_name,
        candidate_version=candidate_version,
        runtime_version=runtime_version,
        minimum_runtime_version=minimum_runtime_version,
        maximum_runtime_version=maximum_runtime_version,
        compatible=True,
        reason="RUNTIME_COMPATIBLE",
    )


# Public aliases.
runtime_compatibility_check = check_runtime_compatibility
is_runtime_compatible = check_runtime_compatibility


__all__ = [
    "RuntimeCompatibilityResult",
    "RuntimeCompatibilityInput",
    "check_runtime_compatibility",
    "runtime_compatibility_check",
    "is_runtime_compatible",
]
