from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.package_name_normalization import (
    NormalizedPackageName,
    PackageNameNormalizationResult,
    normalize_package_name,
    normalize_package_names,
)


@dataclass(frozen=True)
class Package:
    name: str
    source: Optional[str] = None


def test_package_name_is_lowercased():
    result = normalize_package_names(
        [Package("Requests")]
    )

    assert result.normalized is True
    assert result.status == "NORMALIZED"
    assert result.packages[0].normalized_name == "requests"


def test_package_name_whitespace_is_trimmed():
    result = normalize_package_names(
        [Package("  Requests  ")]
    )

    assert result.packages[0].original_name == "  Requests  "
    assert result.packages[0].normalized_name == "requests"


def test_scoped_package_is_normalized():
    result = normalize_package_names(
        [Package("@Scope/Package")]
    )

    assert result.packages[0].normalized_name == "@scope/package"


def test_scoped_package_whitespace_is_trimmed():
    result = normalize_package_names(
        [Package("  @Scope/Package  ")]
    )

    assert result.packages[0].normalized_name == "@scope/package"


def test_scoped_package_structure_is_preserved():
    result = normalize_package_names(
        [Package("@babel/Core")]
    )

    assert result.packages[0].normalized_name == "@babel/core"


def test_source_is_preserved():
    result = normalize_package_names(
        [Package("Requests", "npm")]
    )

    assert result.packages[0].source == "npm"


def test_source_whitespace_is_trimmed():
    result = normalize_package_names(
        [Package("Requests", "  npm  ")]
    )

    assert result.packages[0].source == "npm"


def test_empty_source_becomes_none():
    result = normalize_package_names(
        [Package("Requests", "   ")]
    )

    assert result.packages[0].source is None


def test_none_inventory_is_rejected():
    result = normalize_package_names(None)

    assert result.normalized is False
    assert result.status == "PACKAGES_IS_NONE"
    assert result.packages == ()


def test_string_inventory_is_rejected():
    result = normalize_package_names("requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_PACKAGE_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = normalize_package_names(b"requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_PACKAGE_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = normalize_package_names(123)

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_PACKAGE_COLLECTION"


def test_invalid_package_object_is_rejected():
    result = normalize_package_names([object()])

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE"


def test_invalid_name_type_is_rejected():
    result = normalize_package_names(
        [Package(123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_empty_name_is_rejected():
    result = normalize_package_names(
        [Package("")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_whitespace_only_name_is_rejected():
    result = normalize_package_names(
        [Package("   ")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_invalid_scoped_name_is_rejected():
    result = normalize_package_names(
        [Package("@scope")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_invalid_scoped_package_is_rejected():
    result = normalize_package_names(
        [Package("@scope/")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_invalid_unscoped_slash_is_rejected():
    result = normalize_package_names(
        [Package("foo/bar")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_internal_whitespace_is_rejected():
    result = normalize_package_names(
        [Package("foo bar")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_scoped_internal_whitespace_is_rejected():
    result = normalize_package_names(
        [Package("@foo/bar baz")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_NAME"


def test_invalid_source_type_is_rejected():
    result = normalize_package_names(
        [Package("requests", 123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_PACKAGE_SOURCE"


def test_multiple_packages_preserve_input_order():
    result = normalize_package_names(
        [
            Package("Zlib"),
            Package("Requests"),
            Package("@Scope/Package"),
        ]
    )

    assert [
        item.normalized_name
        for item in result.packages
    ] == [
        "zlib",
        "requests",
        "@scope/package",
    ]


def test_duplicates_are_preserved():
    result = normalize_package_names(
        [
            Package("Requests"),
            Package("requests"),
        ]
    )

    assert len(result.packages) == 2
    assert [
        item.normalized_name
        for item in result.packages
    ] == ["requests", "requests"]


def test_original_name_is_preserved():
    result = normalize_package_names(
        [Package("  Requests  ")]
    )

    assert result.packages[0].original_name == "  Requests  "


def test_empty_inventory_is_valid():
    result = normalize_package_names([])

    assert result.normalized is True
    assert result.status == "NORMALIZED"
    assert result.packages == ()


def test_result_type_is_correct():
    result = normalize_package_names(
        [Package("requests")]
    )

    assert isinstance(
        result,
        PackageNameNormalizationResult,
    )


def test_package_type_is_correct():
    result = normalize_package_names(
        [Package("requests")]
    )

    assert isinstance(
        result.packages[0],
        NormalizedPackageName,
    )


def test_single_package_helper():
    result = normalize_package_name(
        Package("Requests")
    )

    assert result.normalized is True
    assert result.packages[0].normalized_name == "requests"


def test_result_is_immutable():
    result = normalize_package_names(
        [Package("requests")]
    )

    with pytest.raises(AttributeError):
        result.normalized = False


def test_normalized_package_is_immutable():
    result = normalize_package_names(
        [Package("requests")]
    )

    with pytest.raises(AttributeError):
        result.packages[0].normalized_name = "changed"


def test_input_collection_is_not_modified():
    packages = [
        Package("  Requests  "),
        Package("  Axios  "),
    ]

    original = list(packages)

    normalize_package_names(packages)

    assert packages == original
