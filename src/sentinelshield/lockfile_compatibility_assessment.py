from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class LockfileCompatibilityInput:
    package_name: Optional[str]
    candidate_version: str
    lockfile_version: Optional[str]
    required_version: Optional[str] = None


@dataclass(frozen=True)
class LockfileCompatibilityResult:
    package_name: Optional[str]
    candidate_version: str
    lockfile_version: Optional[str]
    required_version: Optional[str]
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


def _normalize_optional_version(
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


def assess_lockfile_compatibility(
    package_name: Optional[str],
    candidate_version: str,
    lockfile_version: Optional[str],
    required_version: Optional[str] = None,
) -> LockfileCompatibilityResult:
    if package_name is not None:
        if not isinstance(package_name, str):
            raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")
        package_name = package_name.strip()

    if not isinstance(candidate_version, str):
        raise TypeError("CANDIDATE_VERSION_MUST_BE_STRING")

    candidate_version = candidate_version.strip()
    candidate_tuple = _parse_version(candidate_version)

    lockfile_version = _normalize_optional_version(
        lockfile_version,
        "LOCKFILE_VERSION",
    )

    required_version = _normalize_optional_version(
        required_version,
        "REQUIRED_VERSION",
    )

    # No locked version means there is no concrete lockfile
    # version against which the candidate can conflict.
    if lockfile_version is None:
        if required_version is not None:
            required_tuple = _parse_version(required_version)

            if candidate_tuple != required_tuple:
                return LockfileCompatibilityResult(
                    package_name=package_name,
                    candidate_version=candidate_version,
                    lockfile_version=None,
                    required_version=required_version,
                    compatible=False,
                    reason="CANDIDATE_DOES_NOT_MATCH_REQUIRED_VERSION",
                )

        return LockfileCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            lockfile_version=None,
            required_version=required_version,
            compatible=True,
            reason="NO_LOCKED_VERSION",
        )

    lockfile_tuple = _parse_version(lockfile_version)

    # If an explicit required version exists, the candidate must
    # satisfy it and the lockfile must represent the same required
    # version.
    if required_version is not None:
        required_tuple = _parse_version(required_version)

        if candidate_tuple != required_tuple:
            return LockfileCompatibilityResult(
                package_name=package_name,
                candidate_version=candidate_version,
                lockfile_version=lockfile_version,
                required_version=required_version,
                compatible=False,
                reason="CANDIDATE_DOES_NOT_MATCH_REQUIRED_VERSION",
            )

        if lockfile_tuple != required_tuple:
            return LockfileCompatibilityResult(
                package_name=package_name,
                candidate_version=candidate_version,
                lockfile_version=lockfile_version,
                required_version=required_version,
                compatible=False,
                reason="LOCKFILE_DOES_NOT_MATCH_REQUIRED_VERSION",
            )

    # Without an explicit required version, the candidate is
    # compatible when it represents the exact locked version.
    elif candidate_tuple != lockfile_tuple:
        return LockfileCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            lockfile_version=lockfile_version,
            required_version=None,
            compatible=False,
            reason="CANDIDATE_DIFFERS_FROM_LOCKFILE",
        )

    return LockfileCompatibilityResult(
        package_name=package_name,
        candidate_version=candidate_version,
        lockfile_version=lockfile_version,
        required_version=required_version,
        compatible=True,
        reason="LOCKFILE_COMPATIBLE",
    )


# Public aliases.
lockfile_compatibility_assessment = assess_lockfile_compatibility
check_lockfile_compatibility = assess_lockfile_compatibility
is_lockfile_compatible = assess_lockfile_compatibility


__all__ = [
    "LockfileCompatibilityInput",
    "LockfileCompatibilityResult",
    "assess_lockfile_compatibility",
    "lockfile_compatibility_assessment",
    "check_lockfile_compatibility",
    "is_lockfile_compatible",
]
