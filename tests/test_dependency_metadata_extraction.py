from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.dependency_metadata_extraction import (
    DependencyMetadata,
    DependencyMetadataExtractionResult,
    extract_dependency_metadata,
)


@dataclass(frozen=True)
class InputDependency:
    name: str
    version: Optional[str] = None
    source: Optional[str] = None
    integrity: Optional[str] = None
    hash: Optional[str] = None
    dependency_type: Optional[str] = None


def test_all_metadata_is_extracted():
    result = extract_dependency_metadata(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "pypi",
                "sha256-ABC",
                "sha256:ABC",
                "production",
            )
        ]
    )

    assert result.extracted is True
    assert result.status == "EXTRACTED"
    assert result.dependencies == (
        DependencyMetadata(
            "requests",
            "2.32.0",
            "pypi",
            "sha256-ABC",
            "sha256:ABC",
            "production",
        ),
    )


def test_optional_metadata_is_allowed():
    result = extract_dependency_metadata(
        [InputDependency("requests")]
    )

    assert result.extracted is True
    assert result.dependencies[0] == DependencyMetadata(
        "requests",
        None,
        None,
        None,
        None,
        None,
    )


def test_version_is_preserved():
    result = extract_dependency_metadata(
        [InputDependency("requests", ">=2.0,<3.0")]
    )

    assert result.dependencies[0].version == ">=2.0,<3.0"


def test_source_is_preserved():
    result = extract_dependency_metadata(
        [InputDependency("requests", source="pypi")]
    )

    assert result.dependencies[0].source == "pypi"


def test_integrity_is_preserved():
    result = extract_dependency_metadata(
        [InputDependency("requests", integrity="sha256-ABC")]
    )

    assert result.dependencies[0].integrity == "sha256-ABC"


def test_hash_is_preserved():
    result = extract_dependency_metadata(
        [InputDependency("requests", hash="sha256:ABC")]
    )

    assert result.dependencies[0].hash == "sha256:ABC"


def test_dependency_type_is_preserved():
    result = extract_dependency_metadata(
        [InputDependency("requests", dependency_type="production")]
    )

    assert result.dependencies[0].dependency_type == "production"


def test_name_is_normalized():
    result = extract_dependency_metadata(
        [InputDependency("  requests  ")]
    )

    assert result.dependencies[0].name == "requests"


def test_string_metadata_is_trimmed():
    result = extract_dependency_metadata(
        [
            InputDependency(
                "requests",
                " 2.32.0 ",
                " pypi ",
                " sha256-A ",
                " sha256:A ",
                " production ",
            )
        ]
    )

    item = result.dependencies[0]

    assert item.version == "2.32.0"
    assert item.source == "pypi"
    assert item.integrity == "sha256-A"
    assert item.hash == "sha256:A"
    assert item.dependency_type == "production"


def test_empty_optional_values_become_none():
    result = extract_dependency_metadata(
        [
            InputDependency(
                "requests",
                " ",
                " ",
                " ",
                " ",
                " ",
            )
        ]
    )

    assert result.dependencies[0] == DependencyMetadata(
        "requests",
        None,
        None,
        None,
        None,
        None,
    )


def test_multiple_dependencies_are_preserved():
    result = extract_dependency_metadata(
        [
            InputDependency("requests", "2.32.0"),
            InputDependency("urllib3", "2.2.2"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "requests",
        "urllib3",
    ]


def test_input_order_is_preserved():
    result = extract_dependency_metadata(
        [
            InputDependency("zlib"),
            InputDependency("axios"),
            InputDependency("express"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "zlib",
        "axios",
        "express",
    ]


def test_none_inventory():
    result = extract_dependency_metadata(None)

    assert result.extracted is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.dependencies == ()


def test_string_inventory():
    result = extract_dependency_metadata("requests")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory():
    result = extract_dependency_metadata(b"requests")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory():
    result = extract_dependency_metadata(123)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_object():
    result = extract_dependency_metadata([object()])

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_name():
    result = extract_dependency_metadata(
        [InputDependency("")]
    )

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_version():
    result = extract_dependency_metadata(
        [InputDependency("requests", version=123)]
    )

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_invalid_source():
    result = extract_dependency_metadata(
        [InputDependency("requests", source=123)]
    )

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_invalid_integrity():
    result = extract_dependency_metadata(
        [InputDependency("requests", integrity=123)]
    )

    assert result.extracted is False
    assert result.status == "INVALID_INTEGRITY"


def test_invalid_hash():
    result = extract_dependency_metadata(
        [InputDependency("requests", hash=123)]
    )

    assert result.extracted is False
    assert result.status == "INVALID_HASH"


def test_invalid_dependency_type():
    result = extract_dependency_metadata(
        [InputDependency("requests", dependency_type=123)]
    )

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_TYPE"


def test_result_type():
    result = extract_dependency_metadata(
        [InputDependency("requests")]
    )

    assert isinstance(
        result,
        DependencyMetadataExtractionResult,
    )


def test_metadata_type():
    result = extract_dependency_metadata(
        [InputDependency("requests")]
    )

    assert isinstance(
        result.dependencies[0],
        DependencyMetadata,
    )


def test_result_is_immutable():
    result = extract_dependency_metadata(
        [InputDependency("requests")]
    )

    with pytest.raises(AttributeError):
        result.extracted = False


def test_metadata_is_immutable():
    result = extract_dependency_metadata(
        [InputDependency("requests")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_empty_inventory():
    result = extract_dependency_metadata([])

    assert result.extracted is True
    assert result.status == "EXTRACTED"
    assert result.dependencies == ()


def test_input_collection_is_not_modified():
    dependencies = [
        InputDependency("zlib", "1.0.0"),
        InputDependency("requests", "2.32.0"),
    ]

    original = list(dependencies)

    extract_dependency_metadata(dependencies)

    assert dependencies == original


def test_missing_optional_attributes_are_supported():
    class MinimalDependency:
        name = "requests"

    result = extract_dependency_metadata(
        [MinimalDependency()]
    )

    assert result.extracted is True
    assert result.dependencies[0].name == "requests"
    assert result.dependencies[0].version is None
    assert result.dependencies[0].source is None
