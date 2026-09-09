from dataclasses import dataclass
from typing import Optional

import pytest

from sentinelshield.dependency_blast_radius_calculation import (
    BlastRadiusResult,
    DependencyNode,
    calculate_dependency_blast_radius,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None


def test_blast_radius_is_calculated():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.32.0"),
        [
            Dependency("app", "1.0.0"),
            Dependency("service", "2.0.0"),
        ],
    )

    assert result.calculated is True
    assert result.status == "CALCULATED"
    assert result.blast_radius == 2


def test_dependents_are_preserved():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.32.0"),
        [Dependency("app", "1.0.0")],
    )

    assert result.affected_dependents == (
        DependencyNode("app", "1.0.0"),
    )


def test_empty_dependents():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.32.0"),
        [],
    )

    assert result.calculated is True
    assert result.blast_radius == 0
    assert result.affected_dependents == ()


def test_none_dependency():
    result = calculate_dependency_blast_radius(None, [])

    assert result.calculated is False
    assert result.status == "DEPENDENCY_IS_NONE"


def test_none_dependents():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.32.0"),
        None,
    )

    assert result.calculated is False
    assert result.status == "DEPENDENTS_IS_NONE"


def test_string_dependents_rejected():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.32.0"),
        "app",
    )

    assert result.calculated is False
    assert result.status == "UNSUPPORTED_DEPENDENTS"


def test_bytes_dependents_rejected():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.32.0"),
        b"app",
    )

    assert result.calculated is False
    assert result.status == "UNSUPPORTED_DEPENDENTS"


def test_invalid_dependency_rejected():
    result = calculate_dependency_blast_radius(object(), [])

    assert result.calculated is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_dependency_name():
    result = calculate_dependency_blast_radius(
        Dependency("", "1.0.0"),
        [],
    )

    assert result.calculated is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_dependency_version():
    result = calculate_dependency_blast_radius(
        Dependency("requests", 123),
        [],
    )

    assert result.calculated is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_invalid_dependent():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [object()],
    )

    assert result.calculated is False
    assert result.status == "INVALID_DEPENDENT"


def test_invalid_dependent_name():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [Dependency("", "1.0.0")],
    )

    assert result.calculated is False
    assert result.status == "INVALID_DEPENDENT_NAME"


def test_invalid_dependent_version():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [Dependency("app", 123)],
    )

    assert result.calculated is False
    assert result.status == "INVALID_DEPENDENT_VERSION"


def test_duplicate_dependents_count_once():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [
            Dependency("app", "1.0.0"),
            Dependency("app", "1.0.0"),
        ],
    )

    assert result.blast_radius == 1


def test_target_dependency_is_not_counted():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [
            Dependency("requests", "2.0.0"),
            Dependency("app", "1.0.0"),
        ],
    )

    assert result.blast_radius == 1


def test_different_versions_are_distinct():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [
            Dependency("app", "1.0.0"),
            Dependency("app", "2.0.0"),
        ],
    )

    assert result.blast_radius == 2


def test_names_are_trimmed():
    result = calculate_dependency_blast_radius(
        Dependency(" requests ", "2.0.0"),
        [Dependency(" app ", "1.0.0")],
    )

    assert result.dependency.name == "requests"
    assert result.affected_dependents[0].name == "app"


def test_deterministic_order():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [
            Dependency("zlib", "1.0.0"),
            Dependency("app", "1.0.0"),
            Dependency("backend", "1.0.0"),
        ],
    )

    assert [x.name for x in result.affected_dependents] == [
        "app",
        "backend",
        "zlib",
    ]


def test_result_type():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [],
    )

    assert isinstance(result, BlastRadiusResult)


def test_node_type():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [Dependency("app", "1.0.0")],
    )

    assert isinstance(result.dependency, DependencyNode)
    assert isinstance(result.affected_dependents[0], DependencyNode)


def test_result_is_immutable():
    result = calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        [],
    )

    with pytest.raises(AttributeError):
        result.calculated = False


def test_input_is_not_modified():
    dependents = [
        Dependency("zlib", "1.0.0"),
        Dependency("app", "1.0.0"),
    ]
    original = list(dependents)

    calculate_dependency_blast_radius(
        Dependency("requests", "2.0.0"),
        dependents,
    )

    assert dependents == original
