from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.dependency_identifier_normalization import (
    DependencyIdentifier,
    DependencyIdentifierNormalizationResult,
    normalize_dependency_identifier,
    normalize_dependency_identifiers,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    identifier: str
    source: Optional[str] = None


def test_valid_identifier_is_normalized():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0")]
    )

    assert result.normalized is True
    assert result.status == "NORMALIZED"
    assert result.dependencies == (
        DependencyIdentifier(
            name="requests",
            identifier="requests@2.32.0",
        ),
    )


def test_name_whitespace_is_removed():
    result = normalize_dependency_identifiers(
        [Dependency("  requests  ", "  requests@2.32.0  ")]
    )

    assert result.dependencies[0].name == "requests"
    assert result.dependencies[0].identifier == "requests@2.32.0"


def test_identifier_is_preserved():
    identifier = "pkg:npm/requests@2.32.0"

    result = normalize_dependency_identifiers(
        [Dependency("requests", identifier)]
    )

    assert result.dependencies[0].identifier == identifier


def test_source_is_preserved():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0", "npm")]
    )

    assert result.dependencies[0].source == "npm"


def test_source_whitespace_is_normalized():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0", "  npm  ")]
    )

    assert result.dependencies[0].source == "npm"


def test_empty_source_becomes_none():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0", "   ")]
    )

    assert result.dependencies[0].source is None


def test_none_inventory_is_rejected():
    result = normalize_dependency_identifiers(None)

    assert result.normalized is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.dependencies == ()


def test_string_inventory_is_rejected():
    result = normalize_dependency_identifiers("requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = normalize_dependency_identifiers(b"requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = normalize_dependency_identifiers(123)

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_object_is_rejected():
    result = normalize_dependency_identifiers([object()])

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY"


def test_missing_identifier_is_rejected():
    class MissingIdentifier:
        name = "requests"

    result = normalize_dependency_identifiers(
        [MissingIdentifier()]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_name_type_is_rejected():
    result = normalize_dependency_identifiers(
        [Dependency(123, "requests@2.32.0")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_empty_name_is_rejected():
    result = normalize_dependency_identifiers(
        [Dependency("   ", "requests@2.32.0")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_identifier_type_is_rejected():
    result = normalize_dependency_identifiers(
        [Dependency("requests", 123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_IDENTIFIER"


def test_empty_identifier_is_rejected():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "   ")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_IDENTIFIER"


def test_invalid_source_type_is_rejected():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0", 123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_multiple_dependencies_are_preserved_in_input_order():
    dependencies = [
        Dependency("zlib", "zlib@1.0.0"),
        Dependency("requests", "requests@2.32.0"),
        Dependency("express", "express@4.19.0"),
    ]

    result = normalize_dependency_identifiers(dependencies)

    assert [item.name for item in result.dependencies] == [
        "zlib",
        "requests",
        "express",
    ]


def test_duplicate_identifiers_are_preserved():
    dependencies = [
        Dependency("requests", "requests@2.32.0"),
        Dependency("requests", "requests@2.32.0"),
    ]

    result = normalize_dependency_identifiers(dependencies)

    assert len(result.dependencies) == 2


def test_common_identifier_forms_are_preserved():
    identifiers = [
        "requests@2.32.0",
        "pkg:npm/requests@2.32.0",
        "npm:requests@2.32.0",
        "github:user/project",
    ]

    result = normalize_dependency_identifiers(
        [
            Dependency(f"pkg-{index}", identifier)
            for index, identifier in enumerate(identifiers)
        ]
    )

    assert [
        item.identifier for item in result.dependencies
    ] == identifiers


def test_result_type_is_correct():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0")]
    )

    assert isinstance(
        result,
        DependencyIdentifierNormalizationResult,
    )


def test_dependency_type_is_correct():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0")]
    )

    assert isinstance(
        result.dependencies[0],
        DependencyIdentifier,
    )


def test_single_dependency_helper():
    result = normalize_dependency_identifier(
        Dependency("requests", "requests@2.32.0")
    )

    assert result.normalized is True
    assert len(result.dependencies) == 1


def test_result_is_immutable():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.normalized = False


def test_dependency_result_is_immutable():
    result = normalize_dependency_identifiers(
        [Dependency("requests", "requests@2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_input_collection_is_not_modified():
    dependencies = [
        Dependency("  requests  ", "  requests@2.32.0  "),
    ]

    original = list(dependencies)

    normalize_dependency_identifiers(dependencies)

    assert dependencies == original
