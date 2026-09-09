from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.normalized_dependency_inventory import (
    NormalizedDependency,
    NormalizedDependencyInventoryResult,
    build_normalized_dependency_inventory,
    normalize_dependency_inventory,
)


@dataclass(frozen=True)
class InputDependency:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"
    source: Optional[str] = None


def test_dependency_is_normalized():
    result = build_normalized_dependency_inventory(
        [
            InputDependency(
                "  Requests  ",
                " 2.32.0 ",
                " PRODUCTION ",
                " dependencies ",
            )
        ]
    )

    assert result.normalized is True
    assert result.status == "NORMALIZED"
    assert result.dependencies == (
        NormalizedDependency(
            "requests",
            "2.32.0",
            "production",
            "dependencies",
        ),
    )


def test_name_is_casefolded():
    result = build_normalized_dependency_inventory(
        [InputDependency("ReQuEsTs", "2.32.0")]
    )

    assert result.dependencies[0].name == "requests"


def test_dependency_type_is_lowercase():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", "1.0.0", "  DEVELOPMENT  ")]
    )

    assert result.dependencies[0].dependency_type == "development"


def test_version_whitespace_is_removed():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", "  >=1.2.0  ")]
    )

    assert result.dependencies[0].version == ">=1.2.0"


def test_source_whitespace_is_removed():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", "1.0.0", "production", " dependencies ")]
    )

    assert result.dependencies[0].source == "dependencies"


def test_none_version_is_preserved():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", None)]
    )

    assert result.dependencies[0].version is None


def test_none_source_is_preserved():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", "1.0.0", "production", None)]
    )

    assert result.dependencies[0].source is None


def test_empty_inventory():
    result = build_normalized_dependency_inventory([])

    assert result.normalized is True
    assert result.status == "NORMALIZED"
    assert result.dependencies == ()


def test_none_inventory():
    result = build_normalized_dependency_inventory(None)

    assert result.normalized is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.dependencies == ()


def test_string_inventory():
    result = build_normalized_dependency_inventory("requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory():
    result = build_normalized_dependency_inventory(b"requests")

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory():
    result = build_normalized_dependency_inventory(123)

    assert result.normalized is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency():
    result = build_normalized_dependency_inventory([object()])

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_name():
    result = build_normalized_dependency_inventory(
        [InputDependency("   ", "1.0.0")]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_version():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", 123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_invalid_dependency_type():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", "1.0.0", 123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_TYPE"


def test_invalid_source():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", "1.0.0", "production", 123)]
    )

    assert result.normalized is False
    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_multiple_dependencies_are_normalized():
    result = build_normalized_dependency_inventory(
        [
            InputDependency("Requests", "2.32.0"),
            InputDependency("URLLIB3", "2.2.2"),
            InputDependency("PyTest", "8.3.0", "DEVELOPMENT"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "pytest",
        "requests",
        "urllib3",
    ]


def test_deterministic_sorting():
    result = build_normalized_dependency_inventory(
        [
            InputDependency("zlib", "1.0.0"),
            InputDependency("requests", "2.32.0"),
            InputDependency("axios", "1.7.0"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "axios",
        "requests",
        "zlib",
    ]


def test_same_name_versions_are_sorted():
    result = build_normalized_dependency_inventory(
        [
            InputDependency("pkg", "2.0.0"),
            InputDependency("pkg", "1.0.0"),
            InputDependency("pkg", "1.5.0"),
        ]
    )

    assert [item.version for item in result.dependencies] == [
        "1.0.0",
        "1.5.0",
        "2.0.0",
    ]


def test_same_name_types_are_sorted():
    result = build_normalized_dependency_inventory(
        [
            InputDependency("pkg", "1.0.0", "production"),
            InputDependency("pkg", "1.0.0", "development"),
            InputDependency("pkg", "1.0.0", "optional"),
        ]
    )

    assert [
        item.dependency_type
        for item in result.dependencies
    ] == [
        "development",
        "optional",
        "production",
    ]


def test_input_is_not_modified():
    dependencies = [
        InputDependency("  Requests  ", " 2.32.0 "),
        InputDependency("urllib3", "2.2.2"),
    ]

    original = list(dependencies)

    build_normalized_dependency_inventory(dependencies)

    assert dependencies == original


def test_generator_is_supported():
    dependencies = (
        InputDependency(name)
        for name in ("Requests", "urllib3")
    )

    result = build_normalized_dependency_inventory(dependencies)

    assert result.normalized is True
    assert [item.name for item in result.dependencies] == [
        "requests",
        "urllib3",
    ]


def test_invalid_item_does_not_return_partial_inventory():
    result = build_normalized_dependency_inventory(
        [
            InputDependency("requests", "2.32.0"),
            object(),
        ]
    )

    assert result.normalized is False
    assert result.dependencies == ()
    assert result.status == "INVALID_DEPENDENCY"


def test_result_is_immutable():
    result = build_normalized_dependency_inventory(
        [InputDependency("requests", "2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.normalized = False


def test_dependency_is_immutable():
    result = build_normalized_dependency_inventory(
        [InputDependency("requests", "2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_result_type():
    result = build_normalized_dependency_inventory(
        [InputDependency("requests", "2.32.0")]
    )

    assert isinstance(
        result,
        NormalizedDependencyInventoryResult,
    )


def test_dependency_type():
    result = build_normalized_dependency_inventory(
        [InputDependency("requests", "2.32.0")]
    )

    assert isinstance(
        result.dependencies[0],
        NormalizedDependency,
    )


def test_wrapper_function():
    result = normalize_dependency_inventory(
        [InputDependency("Requests", "2.32.0")]
    )

    assert result.normalized is True
    assert result.dependencies[0].name == "requests"


def test_production_type():
    result = build_normalized_dependency_inventory(
        [InputDependency("requests", "2.32.0", "PRODUCTION")]
    )

    assert result.dependencies[0].dependency_type == "production"


def test_optional_type():
    result = build_normalized_dependency_inventory(
        [InputDependency("pkg", "1.0.0", "OPTIONAL")]
    )

    assert result.dependencies[0].dependency_type == "optional"


def test_peer_type():
    result = build_normalized_dependency_inventory(
        [InputDependency("react", "18.3.0", "PEER")]
    )

    assert result.dependencies[0].dependency_type == "peer"


def test_normalized_inventory_contains_no_original_objects():
    source = InputDependency("Requests", "2.32.0")

    result = build_normalized_dependency_inventory([source])

    assert result.dependencies[0] is not source
