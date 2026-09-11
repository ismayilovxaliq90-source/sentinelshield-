from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class DependencyVersionDiffResult:
    """
    Immutable result of dependency-version diff validation.
    """

    changed: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]
    unexpected: tuple[str, ...]
    status: str
    reason: str


def _normalize_inventory(
    inventory: Mapping[str, Any],
) -> dict[str, str]:
    """
    Normalize a dependency inventory without modifying
    the caller's object.
    """

    if not isinstance(inventory, Mapping):
        raise TypeError("INVENTORY_MUST_BE_MAPPING")

    normalized: dict[str, str] = {}

    for name, version in inventory.items():

        if not isinstance(name, str):
            raise ValueError(
                "INVALID_DEPENDENCY_IDENTIFIER"
            )

        if not isinstance(version, str):
            raise ValueError(
                "INVALID_DEPENDENCY_VERSION"
            )

        normalized_name = name.strip()
        normalized_version = version.strip()

        if not normalized_name:
            raise ValueError(
                "INVALID_DEPENDENCY_IDENTIFIER"
            )

        if not normalized_version:
            raise ValueError(
                "INVALID_DEPENDENCY_VERSION"
            )

        normalized[normalized_name] = normalized_version

    return normalized


def _normalize_expected_changes(
    expected_changes: Mapping[str, Any],
) -> dict[str, str]:
    """
    Normalize the approved remediation version scope.
    """

    if not isinstance(expected_changes, Mapping):
        raise TypeError(
            "EXPECTED_SCOPE_MUST_BE_MAPPING"
        )

    normalized: dict[str, str] = {}

    for name, version in expected_changes.items():

        if not isinstance(name, str):
            raise ValueError(
                "INVALID_EXPECTED_DEPENDENCY"
            )

        if not isinstance(version, str):
            raise ValueError(
                "INVALID_EXPECTED_VERSION"
            )

        normalized_name = name.strip()
        normalized_version = version.strip()

        if not normalized_name:
            raise ValueError(
                "INVALID_EXPECTED_DEPENDENCY"
            )

        if not normalized_version:
            raise ValueError(
                "INVALID_EXPECTED_VERSION"
            )

        normalized[normalized_name] = normalized_version

    return normalized


def validate_dependency_version_diff(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    expected_changes: Mapping[str, Any] | None = None,
) -> DependencyVersionDiffResult:
    """
    TASK 219 — Dependency Version Diff Validation.

    Compares dependency versions between a baseline inventory
    and the current post-remediation inventory.

    This function is READ-ONLY.

    It does not:
        - install packages
        - execute package managers
        - modify manifests
        - modify lockfiles
        - modify source code
        - execute project code
        - perform rollback

    Those operations belong to the Server execution phase.
    """

    if expected_changes is None:
        expected_changes = {}

    try:
        before = _normalize_inventory(baseline)
        after = _normalize_inventory(current)
        expected = _normalize_expected_changes(
            expected_changes
        )

    except (TypeError, ValueError) as exc:
        return DependencyVersionDiffResult(
            changed=(),
            added=(),
            removed=(),
            unexpected=(),
            status="INVALID_INPUT",
            reason=str(exc),
        )

    before_names = set(before)
    after_names = set(after)

    # --------------------------------------------------------
    # VERSION CHANGES
    # --------------------------------------------------------

    changed = tuple(
        sorted(
            name
            for name in before_names & after_names
            if before[name] != after[name]
        )
    )

    # --------------------------------------------------------
    # NEW DEPENDENCIES
    # --------------------------------------------------------

    added = tuple(
        sorted(
            after_names - before_names
        )
    )

    # --------------------------------------------------------
    # REMOVED DEPENDENCIES
    # --------------------------------------------------------

    removed = tuple(
        sorted(
            before_names - after_names
        )
    )

    # --------------------------------------------------------
    # UNEXPECTED CHANGES
    # --------------------------------------------------------

    unexpected_names: set[str] = set()

    # Changed dependencies must match the approved
    # target version.
    for name in changed:
        approved_version = expected.get(name)

        if approved_version is None:
            unexpected_names.add(name)
            continue

        if after[name] != approved_version:
            unexpected_names.add(name)

    # Added dependencies must be explicitly approved.
    for name in added:
        approved_version = expected.get(name)

        if approved_version is None:
            unexpected_names.add(name)
            continue

        if after[name] != approved_version:
            unexpected_names.add(name)

    # Removed dependencies are unexpected in this validation
    # because TASK 219 validates dependency-version scope.
    for name in removed:
        unexpected_names.add(name)

    unexpected = tuple(
        sorted(unexpected_names)
    )

    # --------------------------------------------------------
    # RESULT STATUS
    # --------------------------------------------------------

    if unexpected:
        status = "UNEXPECTED_CHANGES"
        reason = (
            "DEPENDENCY_VERSION_DIFF_CONTAINS_"
            "UNEXPECTED_CHANGES"
        )

    elif changed or added or removed:
        status = "VALIDATED"
        reason = (
            "DEPENDENCY_VERSION_DIFF_VALIDATED"
        )

    else:
        status = "NO_CHANGES"
        reason = (
            "NO_DEPENDENCY_VERSION_CHANGES"
        )

    return DependencyVersionDiffResult(
        changed=changed,
        added=added,
        removed=removed,
        unexpected=unexpected,
        status=status,
        reason=reason,
    )


def validate_dependency_versions(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    expected_changes: Mapping[str, Any] | None = None,
) -> DependencyVersionDiffResult:
    """
    Public compatibility wrapper.
    """

    return validate_dependency_version_diff(
        baseline=baseline,
        current=current,
        expected_changes=expected_changes,
    )
