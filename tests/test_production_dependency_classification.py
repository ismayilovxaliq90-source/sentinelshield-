from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.production_dependency_classification import (
    ProductionDependency,
    ProductionDependencyClassificationResult,
    classify_production_dependencies,
)


@dataclass(frozen=True)
class InputDependency:
    name: str
    version: Optional[str]
    dependency_type: str
    source: Optional[str] = None


def test_production_dependencies_are_classified():
    dependencies = (
        InputDependency("requests", "2.32.0", "production", "dependencies"),
        InputDependency("pytest", "8.3.0", "development", "devDependencies"),
        InputDependency("chalk", "5.3.0", "optional", "optionalDependencies"),
        InputDependency("react", "18.3.0", "peer", "peerDependencies"),
    )

    result = classify_production_dependencies(dependencies)

    assert result.classified is True
    assert result.status == "CLASSIFIED"

    assert result.dependencies == (
        ProductionDependency(
            name="requests",
            version="2.32.0",
            dependency_type="production",
            source="dependencies",
        ),
    )


def test_development_dependencies_are_excluded():
    result = classify_production_dependencies(
        [
            InputDependency("app", "1.0.0", "production"),
            InputDependency("pytest", "8.3.0", "development"),
        ]
    )

    assert [dependency.name for dependency in result.dependencies] == ["app"]


def test_optional_dependencies_are_excluded():
    result = classify_production_dependencies(
        [
            InputDependency("app", "1.0.0", "production"),
            InputDependency("fsevents", "2.3.3", "optional"),
        ]
    )

    assert [dependency.name for dependency in result.dependencies] == ["app"]


def test_peer_dependencies_are_excluded():
    result = classify_production_dependencies(
        [
            InputDependency("app", "1.0.0", "production"),
            InputDependency("react", "^18.0.0", "peer"),
        ]
    )

    assert [dependency.name for dependency in result.dependencies] == ["app"]


def test_empty_inventory_is_valid():
    result = classify_production_dependencies(())

    assert result.classified is True
    assert result.status == "CLASSIFIED"
    assert result.dependencies == ()


def test_none_inventory_is_rejected():
    result = classify_production_dependencies(None)

    assert result.classified is False
    assert result.status == "DEPENDENCIES_IS_NONE"
    assert result.dependencies == ()


def test_string_inventory_is_rejected():
    result = classify_production_dependencies("requests")

    assert result.classified is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_bytes_inventory_is_rejected():
    result = classify_production_dependencies(b"requests")

    assert result.classified is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_inventory_is_rejected():
    result = classify_production_dependencies(123)

    assert result.classified is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_dependency_object_is_rejected():
    result = classify_production_dependencies([object()])

    assert result.classified is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_dependency_name_is_rejected():
    result = classify_production_dependencies(
        [InputDependency("", "1.0.0", "production")]
    )

    assert result.classified is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_whitespace_dependency_name_is_rejected():
    result = classify_production_dependencies(
        [InputDependency("   ", "1.0.0", "production")]
    )

    assert result.classified is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_dependency_version_is_rejected():
    result = classify_production_dependencies(
        [InputDependency("requests", 123, "production")]
    )

    assert result.classified is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_invalid_dependency_type_is_rejected():
    result = classify_production_dependencies(
        [InputDependency("requests", "2.32.0", 123)]
    )

    assert result.classified is False
    assert result.status == "INVALID_DEPENDENCY_TYPE"


def test_invalid_dependency_source_is_rejected():
    result = classify_production_dependencies(
        [InputDependency("requests", "2.32.0", "production", 123)]
    )

    assert result.classified is False
    assert result.status == "INVALID_DEPENDENCY_SOURCE"


def test_dependency_type_is_normalized():
    result = classify_production_dependencies(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "  PRODUCTION  ",
                "dependencies",
            )
        ]
    )

    assert result.classified is True
    assert result.dependencies[0].dependency_type == "production"


def test_dependency_name_is_trimmed():
    result = classify_production_dependencies(
        [
            InputDependency(
                "  requests  ",
                "2.32.0",
                "production",
            )
        ]
    )

    assert result.classified is True
    assert result.dependencies[0].name == "requests"


def test_production_dependencies_are_sorted_deterministically():
    result = classify_production_dependencies(
        [
            InputDependency("zlib", "1.0.0", "production"),
            InputDependency("axios", "1.7.0", "production"),
            InputDependency("express", "4.19.0", "production"),
            InputDependency("Axios", "2.0.0", "production"),
        ]
    )

    assert [dependency.name for dependency in result.dependencies] == [
        "axios",
        "Axios",
        "express",
        "zlib",
    ]


def test_version_is_preserved():
    result = classify_production_dependencies(
        [
            InputDependency(
                "example-package",
                ">=1.2.0,<2.0.0",
                "production",
            )
        ]
    )

    assert result.dependencies[0].version == ">=1.2.0,<2.0.0"


def test_none_version_is_allowed():
    result = classify_production_dependencies(
        [
            InputDependency(
                "example-package",
                None,
                "production",
            )
        ]
    )

    assert result.classified is True
    assert result.dependencies[0].version is None


def test_source_is_preserved():
    result = classify_production_dependencies(
        [
            InputDependency(
                "requests",
                "2.32.0",
                "production",
                "dependencies",
            )
        ]
    )

    assert result.dependencies[0].source == "dependencies"


def test_result_is_immutable():
    result = classify_production_dependencies(
        [InputDependency("requests", "2.32.0", "production")]
    )

    with pytest.raises(AttributeError):
        result.classified = False


def test_dependency_is_immutable():
    dependency = ProductionDependency(
        name="requests",
        version="2.32.0",
        dependency_type="production",
        source="dependencies",
    )

    with pytest.raises(AttributeError):
        dependency.name = "changed"


def test_result_contains_only_production_dependencies():
    result = classify_production_dependencies(
        [
            InputDependency("a", "1.0.0", "production"),
            InputDependency("b", "1.0.0", "development"),
            InputDependency("c", "1.0.0", "optional"),
            InputDependency("d", "1.0.0", "peer"),
            InputDependency("e", "1.0.0", "production"),
        ]
    )

    assert {dependency.name for dependency in result.dependencies} == {
        "a",
        "e",
    }

    assert all(
        dependency.dependency_type == "production"
        for dependency in result.dependencies
    )


def test_input_collection_is_not_modified():
    dependencies = [
        InputDependency("z", "1.0.0", "production"),
        InputDependency("a", "1.0.0", "production"),
    ]

    original = list(dependencies)

    classify_production_dependencies(dependencies)

    assert dependencies == original


def test_result_type_is_correct():
    result = classify_production_dependencies(
        [InputDependency("requests", "2.32.0", "production")]
    )

    assert isinstance(
        result,
        ProductionDependencyClassificationResult,
    )


def test_production_dependency_type_is_correct():
    result = classify_production_dependencies(
        [InputDependency("requests", "2.32.0", "production")]
    )

    dependency = result.dependencies[0]

    assert isinstance(dependency, ProductionDependency)
    assert dependency.dependency_type == "production"
