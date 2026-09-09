from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.package_source_extraction import (
    DependencySource,
    PackageSourceExtractionResult,
    extract_package_sources,
)


@dataclass(frozen=True)
class InputDependency:
    name: str
    version: Optional[str] = None
    source: Optional[str] = None
    dependency_type: str = "production"


def test_registry_source_is_preserved():
    result = extract_package_sources(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "pypi",
            )
        ]
    )

    assert result.extracted is True
    assert result.status == "EXTRACTED"
    assert result.dependencies == (
        DependencySource(
            name="requests",
            source="pypi",
        ),
    )


def test_git_source_is_preserved():
    source = "https://github.com/example/project.git"

    result = extract_package_sources(
        [InputDependency("example", "1.0.0", source)]
    )

    assert result.dependencies[0].source == source


def test_url_source_is_preserved():
    source = "https://example.com/package.tar.gz"

    result = extract_package_sources(
        [InputDependency("example", "1.0.0", source)]
    )

    assert result.dependencies[0].source == source


def test_missing_source_is_allowed():
    result = extract_package_sources(
        [InputDependency("requests", "2.32.0")]
    )

    assert result.extracted is True
    assert result.dependencies[0].source is None


def test_empty_source_becomes_none():
    result = extract_package_sources(
        [InputDependency("requests", "2.32.0", "   ")]
    )

    assert result.dependencies[0].source is None


def test_source_whitespace_is_normalized():
    result = extract_package_sources(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "  pypi  ",
            )
        ]
    )

    assert result.dependencies[0].source == "pypi"


def test_name_whitespace_is_normalized():
    result = extract_package_sources(
        [
            InputDependency(
                "  requests  ",
                "2.32.0",
                "pypi",
            )
        ]
    )

    assert result.dependencies[0].name == "requests"


def test_multiple_sources_are_preserved():
    result = extract_package_sources(
        [
            InputDependency("requests", "2.32.0", "pypi"),
            InputDependency("example", "1.0.0", "git"),
            InputDependency("foo", "3.0.0", "internal"),
        ]
    )

    assert result.dependencies == (
        DependencySource("requests", "pypi"),
        DependencySource("example", "git"),
        DependencySource("foo", "internal"),
    )


def test_input_order_is_preserved():
    result = extract_package_sources(
        [
            InputDependency("zlib", "1.0.0", "registry-a"),
            InputDependency("axios", "1.0.0", "registry-b"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "zlib",
        "axios",
    ]


def test_none_inventory():
    result = extract_package_sources(None)

    assert result.extracted is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.dependencies == ()


def test_string_inventory_is_rejected():
    result = extract_package_sources("requests")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = extract_package_sources(b"requests")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = extract_package_sources(123)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_object():
    result = extract_package_sources([object()])

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_dependency_name():
    result = extract_package_sources(
        [InputDependency("", "1.0.0", "pypi")]
    )

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_dependency_source():
    result = extract_package_sources(
        [InputDependency("requests", "2.32.0", 123)]
    )

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_result_type():
    result = extract_package_sources(
        [InputDependency("requests", "2.32.0", "pypi")]
    )

    assert isinstance(
        result,
        PackageSourceExtractionResult,
    )


def test_dependency_source_type():
    result = extract_package_sources(
        [InputDependency("requests", "2.32.0", "pypi")]
    )

    assert isinstance(
        result.dependencies[0],
        DependencySource,
    )


def test_result_is_immutable():
    result = extract_package_sources(
        [InputDependency("requests", "2.32.0", "pypi")]
    )

    with pytest.raises(AttributeError):
        result.extracted = False


def test_dependency_source_is_immutable():
    result = extract_package_sources(
        [InputDependency("requests", "2.32.0", "pypi")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_empty_inventory():
    result = extract_package_sources([])

    assert result.extracted is True
    assert result.status == "EXTRACTED"
    assert result.dependencies == ()


def test_input_collection_is_not_modified():
    dependencies = [
        InputDependency("zlib", "1.0.0", "pypi"),
        InputDependency("requests", "2.0.0", "pypi"),
    ]

    original = list(dependencies)

    extract_package_sources(dependencies)

    assert dependencies == original
