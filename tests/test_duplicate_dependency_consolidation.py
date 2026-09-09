from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.duplicate_dependency_consolidation import (
    ConsolidatedDependency,
    DuplicateDependencyConsolidationResult,
    consolidate_duplicate_dependencies,
)


@dataclass(frozen=True)
class InputDependency:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"
    source: Optional[str] = None


def test_duplicates_are_consolidated():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("requests", "2.31.0"),
            InputDependency("requests", "2.32.0"),
            InputDependency("pytest", "8.3.0", "development"),
        ]
    )

    assert result.consolidated is True
    assert result.status == "CONSOLIDATED"
    assert result.duplicates_found == 1
    assert result.dependencies == (
        ConsolidatedDependency(
            name="pytest",
            versions=("8.3.0",),
            dependency_types=("development",),
            sources=(),
        ),
        ConsolidatedDependency(
            name="requests",
            versions=("2.31.0", "2.32.0"),
            dependency_types=("production",),
            sources=(),
        ),
    )


def test_unique_dependencies_are_preserved():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("requests", "2.32.0"),
            InputDependency("flask", "3.0.0"),
        ]
    )

    assert result.duplicates_found == 0
    assert len(result.dependencies) == 2


def test_case_insensitive_duplicates():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("Requests", "2.31.0"),
            InputDependency("requests", "2.32.0"),
        ]
    )

    assert result.duplicates_found == 1
    assert len(result.dependencies) == 1
    assert result.dependencies[0].versions == (
        "2.31.0",
        "2.32.0",
    )


def test_duplicate_types_are_consolidated():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("pkg", "1.0.0", "production"),
            InputDependency("pkg", "1.0.0", "development"),
        ]
    )

    assert result.dependencies[0].dependency_types == (
        "development",
        "production",
    )


def test_duplicate_sources_are_consolidated():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("pkg", "1.0.0", "production", "dependencies"),
            InputDependency("pkg", "1.0.0", "production", "lockfile"),
        ]
    )

    assert result.dependencies[0].sources == (
        "dependencies",
        "lockfile",
    )


def test_none_version_is_supported():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("pkg", None),
            InputDependency("pkg", "1.0.0"),
        ]
    )

    assert result.dependencies[0].versions == ("1.0.0",)


def test_empty_inventory_is_valid():
    result = consolidate_duplicate_dependencies([])

    assert result.consolidated is True
    assert result.duplicates_found == 0
    assert result.dependencies == ()
    assert result.status == "CONSOLIDATED"


def test_none_inventory_is_rejected():
    result = consolidate_duplicate_dependencies(None)

    assert result.consolidated is False
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_string_inventory_is_rejected():
    result = consolidate_duplicate_dependencies("requests")

    assert result.consolidated is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = consolidate_duplicate_dependencies(b"requests")

    assert result.consolidated is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_is_rejected():
    result = consolidate_duplicate_dependencies(123)

    assert result.consolidated is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_is_rejected():
    result = consolidate_duplicate_dependencies([object()])

    assert result.consolidated is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_name_is_rejected():
    result = consolidate_duplicate_dependencies(
        [InputDependency("   ", "1.0.0")]
    )

    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_version_is_rejected():
    result = consolidate_duplicate_dependencies(
        [InputDependency("pkg", 123)]
    )

    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_invalid_type_is_rejected():
    result = consolidate_duplicate_dependencies(
        [InputDependency("pkg", "1.0.0", 123)]
    )

    assert result.status == "INVALID_DEPENDENCY_TYPE"


def test_invalid_source_is_rejected():
    result = consolidate_duplicate_dependencies(
        [InputDependency("pkg", "1.0.0", "production", 123)]
    )

    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_input_is_not_modified():
    dependencies = [
        InputDependency("z", "1.0.0"),
        InputDependency("a", "1.0.0"),
        InputDependency("a", "2.0.0"),
    ]

    original = list(dependencies)

    consolidate_duplicate_dependencies(dependencies)

    assert dependencies == original


def test_deterministic_sorting():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("zlib", "1.0.0"),
            InputDependency("requests", "2.0.0"),
            InputDependency("axios", "1.0.0"),
            InputDependency("requests", "2.1.0"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "axios",
        "requests",
        "zlib",
    ]


def test_result_is_immutable():
    result = consolidate_duplicate_dependencies(
        [InputDependency("pkg", "1.0.0")]
    )

    with pytest.raises(AttributeError):
        result.consolidated = False


def test_consolidated_dependency_is_immutable():
    result = consolidate_duplicate_dependencies(
        [InputDependency("pkg", "1.0.0")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_result_type_is_correct():
    result = consolidate_duplicate_dependencies(
        [InputDependency("pkg", "1.0.0")]
    )

    assert isinstance(
        result,
        DuplicateDependencyConsolidationResult,
    )


def test_consolidated_dependency_type_is_correct():
    result = consolidate_duplicate_dependencies(
        [InputDependency("pkg", "1.0.0")]
    )

    assert isinstance(
        result.dependencies[0],
        ConsolidatedDependency,
    )


def test_three_duplicates_count_correctly():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("pkg", "1.0.0"),
            InputDependency("pkg", "1.1.0"),
            InputDependency("pkg", "1.2.0"),
        ]
    )

    assert result.duplicates_found == 2
    assert len(result.dependencies) == 1


def test_duplicate_versions_are_removed():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("pkg", "1.0.0"),
            InputDependency("pkg", "1.0.0"),
        ]
    )

    assert result.duplicates_found == 1
    assert result.dependencies[0].versions == ("1.0.0",)


def test_dependency_type_is_normalized():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("pkg", "1.0.0", "  PRODUCTION  "),
        ]
    )

    assert result.dependencies[0].dependency_types == (
        "production",
    )


def test_name_is_trimmed():
    result = consolidate_duplicate_dependencies(
        [
            InputDependency("  requests  ", "2.32.0"),
        ]
    )

    assert result.dependencies[0].name == "requests"
