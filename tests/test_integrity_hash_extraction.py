from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.integrity_hash_extraction import (
    DependencyIntegrity,
    IntegrityHashExtractionResult,
    extract_integrity_hashes,
)


@dataclass(frozen=True)
class InputDependency:
    name: str
    version: Optional[str] = None
    integrity: Optional[str] = None
    hash: Optional[str] = None
    source: Optional[str] = None


def test_integrity_is_extracted():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "sha256-ABC123",
            )
        ]
    )

    assert result.extracted is True
    assert result.status == "EXTRACTED"
    assert result.dependencies == (
        DependencyIntegrity(
            "requests",
            "sha256-ABC123",
            None,
        ),
    )


def test_hash_is_extracted():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                None,
                "sha256:ABC123",
            )
        ]
    )

    assert result.dependencies[0].hash == "sha256:ABC123"


def test_integrity_and_hash_are_both_preserved():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "sha512-XYZ",
                "sha512:XYZ",
            )
        ]
    )

    item = result.dependencies[0]

    assert item.integrity == "sha512-XYZ"
    assert item.hash == "sha512:XYZ"


def test_missing_integrity_is_allowed():
    result = extract_integrity_hashes(
        [InputDependency("requests", "2.32.0")]
    )

    assert result.extracted is True
    assert result.dependencies[0].integrity is None


def test_missing_hash_is_allowed():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "sha256-ABC",
            )
        ]
    )

    assert result.extracted is True
    assert result.dependencies[0].hash is None


def test_empty_integrity_becomes_none():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "   ",
            )
        ]
    )

    assert result.dependencies[0].integrity is None


def test_empty_hash_becomes_none():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                None,
                "   ",
            )
        ]
    )

    assert result.dependencies[0].hash is None


def test_integrity_whitespace_is_normalized():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "  sha256-ABC  ",
            )
        ]
    )

    assert result.dependencies[0].integrity == "sha256-ABC"


def test_hash_whitespace_is_normalized():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                None,
                "  sha256:ABC  ",
            )
        ]
    )

    assert result.dependencies[0].hash == "sha256:ABC"


def test_name_whitespace_is_normalized():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "  requests  ",
                "2.32.0",
            )
        ]
    )

    assert result.dependencies[0].name == "requests"


def test_multiple_dependencies_are_preserved():
    result = extract_integrity_hashes(
        [
            InputDependency("a", "1.0", "sha256-A", "hash-A"),
            InputDependency("b", "2.0", "sha256-B", "hash-B"),
        ]
    )

    assert result.dependencies == (
        DependencyIntegrity("a", "sha256-A", "hash-A"),
        DependencyIntegrity("b", "sha256-B", "hash-B"),
    )


def test_input_order_is_preserved():
    result = extract_integrity_hashes(
        [
            InputDependency("z", "1.0"),
            InputDependency("a", "1.0"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "z",
        "a",
    ]


def test_none_inventory():
    result = extract_integrity_hashes(None)

    assert result.extracted is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.dependencies == ()


def test_string_inventory_is_rejected():
    result = extract_integrity_hashes("requests")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = extract_integrity_hashes(b"requests")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = extract_integrity_hashes(123)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_object():
    result = extract_integrity_hashes([object()])

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_dependency_name():
    result = extract_integrity_hashes(
        [InputDependency("", "1.0")]
    )

    assert result.extracted is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_integrity():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                123,
            )
        ]
    )

    assert result.extracted is False
    assert result.status == "INVALID_INTEGRITY"


def test_invalid_hash():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                None,
                123,
            )
        ]
    )

    assert result.extracted is False
    assert result.status == "INVALID_HASH"


def test_result_type():
    result = extract_integrity_hashes(
        [InputDependency("requests", "2.32.0")]
    )

    assert isinstance(
        result,
        IntegrityHashExtractionResult,
    )


def test_dependency_integrity_type():
    result = extract_integrity_hashes(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "sha256-A",
                "sha256:A",
            )
        ]
    )

    assert isinstance(
        result.dependencies[0],
        DependencyIntegrity,
    )


def test_result_is_immutable():
    result = extract_integrity_hashes(
        [InputDependency("requests", "2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.extracted = False


def test_dependency_integrity_is_immutable():
    result = extract_integrity_hashes(
        [InputDependency("requests", "2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_empty_inventory():
    result = extract_integrity_hashes([])

    assert result.extracted is True
    assert result.status == "EXTRACTED"
    assert result.dependencies == ()


def test_input_collection_is_not_modified():
    dependencies = [
        InputDependency(
            "z",
            "1.0",
            "sha256-Z",
            "hash-Z",
        ),
        InputDependency(
            "a",
            "1.0",
            "sha256-A",
            "hash-A",
        ),
    ]

    original = list(dependencies)

    extract_integrity_hashes(dependencies)

    assert dependencies == original
