from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.version_normalization import (
    NormalizedDependencyVersion,
    VersionNormalizationResult,
    normalize_dependency_version,
    normalize_dependency_versions,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str]


def test_version_is_preserved():
    result = normalize_dependency_versions(
        [Dependency("requests", "2.32.0")]
    )

    assert result.normalized is True
    assert result.status == "NORMALIZED"
    assert result.dependencies[0].normalized_version == "2.32.0"


def test_version_whitespace_is_removed():
    result = normalize_dependency_versions(
        [Dependency("requests", "  2.32.0  ")]
    )

    assert result.dependencies[0].normalized_version == "2.32.0"


def test_leading_v_is_normalized():
    result = normalize_dependency_versions(
        [Dependency("requests", "v2.32.0")]
    )

    assert result.dependencies[0].normalized_version == "2.32.0"


def test_uppercase_leading_v_is_normalized():
    result = normalize_dependency_versions(
        [Dependency("requests", "V2.32.0")]
    )

    assert result.dependencies[0].normalized_version == "2.32.0"


def test_original_version_is_preserved():
    result = normalize_dependency_versions(
        [Dependency("requests", "  v2.32.0  ")]
    )

    assert result.dependencies[0].original_version == "  v2.32.0  "
    assert result.dependencies[0].normalized_version == "2.32.0"


def test_none_version_is_allowed():
    result = normalize_dependency_versions(
        [Dependency("requests", None)]
    )

    assert result.normalized is True
    assert result.dependencies[0].normalized_version is None


def test_empty_version_is_rejected():
    result = normalize_dependency_versions(
        [Dependency("requests", "")]
    )

    assert result.normalized is False
    assert result.status == "EMPTY_DEPENDENCY_VERSION"


def test_whitespace_only_version_is_rejected():
    result = normalize_dependency_versions(
        [Dependency("requests", "   ")]
    )

    assert result.normalized is False
    assert result.status == "EMPTY_DEPENDENCY_VERSION"


def test_numeric_version_is_rejected():
    result = normalize_dependency_versions(
        [Dependency("requests", 123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_float_version_is_rejected():
    result = normalize_dependency_versions(
        [Dependency("requests", 2.32)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_none_inventory_is_rejected():
    result = normalize_dependency_versions(None)

    assert result.normalized is False
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_string_inventory_is_rejected():
    result = normalize_dependency_versions("requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = normalize_dependency_versions(b"requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = normalize_dependency_versions(123)

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_object_is_rejected():
    result = normalize_dependency_versions([object()])

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_dependency_name_is_rejected():
    result = normalize_dependency_versions(
        [Dependency("", "1.0.0")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_dependency_name_is_trimmed():
    result = normalize_dependency_versions(
        [Dependency("  requests  ", "1.0.0")]
    )

    assert result.dependencies[0].name == "requests"


def test_common_versions_are_preserved():
    versions = [
        "1.0.0",
        "1.2.3-alpha",
        "2.0.0-beta.1",
        "2026.09",
        "1.0.0+build.1",
    ]

    result = normalize_dependency_versions(
        [
            Dependency(f"pkg-{index}", version)
            for index, version in enumerate(versions)
        ]
    )

    assert [
        item.normalized_version
        for item in result.dependencies
    ] == versions


def test_version_constraints_are_not_modified():
    versions = [
        ">=1.2.0",
        "<2.0",
        "^1.2.3",
        "~1.2.3",
        ">=1.0,<2.0",
        "*",
    ]

    result = normalize_dependency_versions(
        [
            Dependency(f"pkg-{index}", version)
            for index, version in enumerate(versions)
        ]
    )

    assert [
        item.normalized_version
        for item in result.dependencies
    ] == versions


def test_multiple_dependencies_preserve_order():
    result = normalize_dependency_versions(
        [
            Dependency("zlib", "1.0.0"),
            Dependency("requests", "2.32.0"),
            Dependency("express", "4.19.0"),
        ]
    )

    assert [
        item.name for item in result.dependencies
    ] == [
        "zlib",
        "requests",
        "express",
    ]


def test_duplicates_are_preserved():
    result = normalize_dependency_versions(
        [
            Dependency("requests", "2.32.0"),
            Dependency("requests", "2.32.0"),
        ]
    )

    assert len(result.dependencies) == 2


def test_empty_inventory_is_valid():
    result = normalize_dependency_versions([])

    assert result.normalized is True
    assert result.status == "NORMALIZED"
    assert result.dependencies == ()


def test_result_type_is_correct():
    result = normalize_dependency_versions(
        [Dependency("requests", "2.32.0")]
    )

    assert isinstance(result, VersionNormalizationResult)


def test_dependency_type_is_correct():
    result = normalize_dependency_versions(
        [Dependency("requests", "2.32.0")]
    )

    assert isinstance(
        result.dependencies[0],
        NormalizedDependencyVersion,
    )


def test_single_dependency_helper():
    result = normalize_dependency_version(
        Dependency("requests", "v2.32.0")
    )

    assert result.normalized is True
    assert result.dependencies[0].normalized_version == "2.32.0"


def test_result_is_immutable():
    result = normalize_dependency_versions(
        [Dependency("requests", "1.0.0")]
    )

    with pytest.raises(AttributeError):
        result.normalized = False


def test_dependency_is_immutable():
    result = normalize_dependency_versions(
        [Dependency("requests", "1.0.0")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_input_collection_is_not_modified():
    dependencies = [
        Dependency("requests", "  v2.32.0  "),
        Dependency("axios", "1.7.0"),
    ]

    original = list(dependencies)

    normalize_dependency_versions(dependencies)

    assert dependencies == original
