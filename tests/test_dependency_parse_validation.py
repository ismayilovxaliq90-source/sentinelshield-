from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.dependency_parse_validation import (
    DependencyParseValidationResult,
    ParsedDependency,
    validate_dependency_parse,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None
    dependency_type: str = "production"
    source: Optional[str] = None


def test_valid_dependency_is_accepted():
    result = validate_dependency_parse(
        [
            Dependency(
                "requests",
                "2.32.0",
                "production",
                "dependencies",
            )
        ]
    )

    assert result.valid is True
    assert result.status == "VALIDATED"
    assert result.dependencies == (
        ParsedDependency(
            "requests",
            "2.32.0",
            "production",
            "dependencies",
        ),
    )


def test_multiple_dependencies_are_preserved():
    dependencies = [
        Dependency("requests", "2.32.0"),
        Dependency("urllib3", "2.2.2"),
        Dependency("pytest", "8.3.0", "development"),
    ]

    result = validate_dependency_parse(dependencies)

    assert result.valid is True
    assert len(result.dependencies) == 3
    assert [item.name for item in result.dependencies] == [
        "requests",
        "urllib3",
        "pytest",
    ]


def test_empty_collection_is_valid():
    result = validate_dependency_parse([])

    assert result.valid is True
    assert result.dependencies == ()
    assert result.status == "VALIDATED"


def test_none_collection_is_rejected():
    result = validate_dependency_parse(None)

    assert result.valid is False
    assert result.dependencies == ()
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_string_collection_is_rejected():
    result = validate_dependency_parse("requests")

    assert result.valid is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_collection_is_rejected():
    result = validate_dependency_parse(b"requests")

    assert result.valid is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_collection_is_rejected():
    result = validate_dependency_parse(123)

    assert result.valid is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_missing_name_is_rejected():
    class DependencyWithoutName:
        version = "1.0.0"

    result = validate_dependency_parse(
        [DependencyWithoutName()]
    )

    assert result.valid is False
    assert result.status == "INVALID_DEPENDENCY"


def test_empty_name_is_rejected():
    result = validate_dependency_parse(
        [Dependency("","1.0.0")]
    )

    assert result.valid is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_whitespace_name_is_rejected():
    result = validate_dependency_parse(
        [Dependency("   ","1.0.0")]
    )

    assert result.valid is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_version_is_rejected():
    result = validate_dependency_parse(
        [Dependency("requests", 123)]
    )

    assert result.valid is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_none_version_is_allowed():
    result = validate_dependency_parse(
        [Dependency("requests", None)]
    )

    assert result.valid is True
    assert result.dependencies[0].version is None


def test_invalid_dependency_type_is_rejected():
    result = validate_dependency_parse(
        [Dependency("requests", "2.32.0", 123)]
    )

    assert result.valid is False
    assert result.status == "INVALID_DEPENDENCY_TYPE"


def test_invalid_source_is_rejected():
    result = validate_dependency_parse(
        [Dependency("requests", "2.32.0", "production", 123)]
    )

    assert result.valid is False
    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_dependency_type_is_normalized():
    result = validate_dependency_parse(
        [
            Dependency(
                "requests",
                "2.32.0",
                "  PRODUCTION  ",
            )
        ]
    )

    assert result.valid is True
    assert result.dependencies[0].dependency_type == "production"


def test_dependency_name_is_trimmed():
    result = validate_dependency_parse(
        [Dependency("  requests  ", "2.32.0")]
    )

    assert result.valid is True
    assert result.dependencies[0].name == "requests"


def test_source_is_preserved():
    result = validate_dependency_parse(
        [
            Dependency(
                "requests",
                "2.32.0",
                "production",
                "dependencies",
            )
        ]
    )

    assert result.dependencies[0].source == "dependencies"


def test_input_collection_is_not_modified():
    dependencies = [
        Dependency("requests", "2.32.0"),
        Dependency("urllib3", "2.2.2"),
    ]

    original = list(dependencies)

    validate_dependency_parse(dependencies)

    assert dependencies == original


def test_invalid_dependency_stops_validation():
    result = validate_dependency_parse(
        [
            Dependency("requests", "2.32.0"),
            object(),
            Dependency("urllib3", "2.2.2"),
        ]
    )

    assert result.valid is False
    assert result.dependencies == ()
    assert result.status == "INVALID_DEPENDENCY"


def test_result_is_immutable():
    result = validate_dependency_parse(
        [Dependency("requests", "2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.valid = False


def test_parsed_dependency_is_immutable():
    result = validate_dependency_parse(
        [Dependency("requests", "2.32.0")]
    )

    with pytest.raises(AttributeError):
        result.dependencies[0].name = "changed"


def test_result_type_is_correct():
    result = validate_dependency_parse(
        [Dependency("requests", "2.32.0")]
    )

    assert isinstance(
        result,
        DependencyParseValidationResult,
    )


def test_parsed_dependency_type_is_correct():
    result = validate_dependency_parse(
        [Dependency("requests", "2.32.0")]
    )

    assert isinstance(
        result.dependencies[0],
        ParsedDependency,
    )


def test_development_dependency_is_valid():
    result = validate_dependency_parse(
        [Dependency("pytest", "8.3.0", "development")]
    )

    assert result.valid is True
    assert result.dependencies[0].dependency_type == "development"


def test_optional_dependency_is_valid():
    result = validate_dependency_parse(
        [Dependency("fsevents", "2.3.3", "optional")]
    )

    assert result.valid is True
    assert result.dependencies[0].dependency_type == "optional"


def test_peer_dependency_is_valid():
    result = validate_dependency_parse(
        [Dependency("react", "18.3.0", "peer")]
    )

    assert result.valid is True
    assert result.dependencies[0].dependency_type == "peer"


def test_generator_input_is_supported():
    dependencies = (
        Dependency(name)
        for name in ("requests", "urllib3")
    )

    result = validate_dependency_parse(dependencies)

    assert result.valid is True
    assert [item.name for item in result.dependencies] == [
        "requests",
        "urllib3",
    ]


def test_no_filesystem_operation_is_required():
    result = validate_dependency_parse(
        [Dependency("requests", "2.32.0")]
    )

    assert result.valid is True
    assert result.status == "VALIDATED"


def test_dependency_order_is_preserved():
    result = validate_dependency_parse(
        [
            Dependency("zlib", "1.0.0"),
            Dependency("axios", "1.7.0"),
            Dependency("express", "4.19.0"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "zlib",
        "axios",
        "express",
    ]
