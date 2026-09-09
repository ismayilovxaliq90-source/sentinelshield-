from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PeerDependencyCompatibilityInput:
    package_name: Optional[str]
    candidate_version: str
    peer_dependency_name: str
    peer_version: str
    minimum_peer_version: Optional[str] = None
    maximum_peer_version: Optional[str] = None


@dataclass(frozen=True)
class PeerDependencyCompatibilityResult:
    package_name: Optional[str]
    candidate_version: str
    peer_dependency_name: str
    peer_version: str
    minimum_peer_version: Optional[str]
    maximum_peer_version: Optional[str]
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


def assess_peer_dependency_compatibility(
    package_name: Optional[str],
    candidate_version: str,
    peer_dependency_name: str,
    peer_version: str,
    minimum_peer_version: Optional[str] = None,
    maximum_peer_version: Optional[str] = None,
) -> PeerDependencyCompatibilityResult:

    if package_name is not None:
        if not isinstance(package_name, str):
            raise TypeError("PACKAGE_NAME_MUST_BE_STRING_OR_NONE")
        package_name = package_name.strip()

    if not isinstance(candidate_version, str):
        raise TypeError("CANDIDATE_VERSION_MUST_BE_STRING")

    if not isinstance(peer_dependency_name, str):
        raise TypeError("PEER_DEPENDENCY_NAME_MUST_BE_STRING")

    if not isinstance(peer_version, str):
        raise TypeError("PEER_VERSION_MUST_BE_STRING")

    candidate_version = candidate_version.strip()
    peer_dependency_name = peer_dependency_name.strip()
    peer_version = peer_version.strip()

    if not peer_dependency_name:
        raise ValueError("PEER_DEPENDENCY_NAME_IS_EMPTY")

    # Validate the dependency candidate itself.
    _parse_version(candidate_version)

    peer_version_tuple = _parse_version(peer_version)

    minimum_peer_version = _validate_optional_version(
        minimum_peer_version,
        "MINIMUM_PEER_VERSION",
    )

    maximum_peer_version = _validate_optional_version(
        maximum_peer_version,
        "MAXIMUM_PEER_VERSION",
    )

    minimum_tuple = (
        _parse_version(minimum_peer_version)
        if minimum_peer_version is not None
        else None
    )

    maximum_tuple = (
        _parse_version(maximum_peer_version)
        if maximum_peer_version is not None
        else None
    )

    if (
        minimum_tuple is not None
        and maximum_tuple is not None
        and minimum_tuple > maximum_tuple
    ):
        raise ValueError("MINIMUM_PEER_EXCEEDS_MAXIMUM_PEER")

    if minimum_tuple is not None and peer_version_tuple < minimum_tuple:
        return PeerDependencyCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            peer_dependency_name=peer_dependency_name,
            peer_version=peer_version,
            minimum_peer_version=minimum_peer_version,
            maximum_peer_version=maximum_peer_version,
            compatible=False,
            reason="PEER_BELOW_MINIMUM",
        )

    if maximum_tuple is not None and peer_version_tuple > maximum_tuple:
        return PeerDependencyCompatibilityResult(
            package_name=package_name,
            candidate_version=candidate_version,
            peer_dependency_name=peer_dependency_name,
            peer_version=peer_version,
            minimum_peer_version=minimum_peer_version,
            maximum_peer_version=maximum_peer_version,
            compatible=False,
            reason="PEER_ABOVE_MAXIMUM",
        )

    return PeerDependencyCompatibilityResult(
        package_name=package_name,
        candidate_version=candidate_version,
        peer_dependency_name=peer_dependency_name,
        peer_version=peer_version,
        minimum_peer_version=minimum_peer_version,
        maximum_peer_version=maximum_peer_version,
        compatible=True,
        reason="PEER_DEPENDENCY_COMPATIBLE",
    )


# Public aliases.
peer_dependency_compatibility_assessment = (
    assess_peer_dependency_compatibility
)
check_peer_dependency_compatibility = (
    assess_peer_dependency_compatibility
)
is_peer_dependency_compatible = (
    assess_peer_dependency_compatibility
)


__all__ = [
    "PeerDependencyCompatibilityInput",
    "PeerDependencyCompatibilityResult",
    "assess_peer_dependency_compatibility",
    "peer_dependency_compatibility_assessment",
    "check_peer_dependency_compatibility",
    "is_peer_dependency_compatible",
]
