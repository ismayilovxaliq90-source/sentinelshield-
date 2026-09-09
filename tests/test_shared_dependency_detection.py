from dataclasses import dataclass
from typing import Optional

from sentinelshield.shared_dependency_detection import (
    DependencyNode,
    SharedDependencyResult,
    detect_shared_dependencies,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str] = None


def test_shared_dependency_is_detected():
    result = detect_shared_dependencies([
        [Dependency("requests", "2.32.0"), Dependency("flask", "3.0.0")],
        [Dependency("requests", "2.32.0"), Dependency("django", "5.0.0")],
    ])

    assert result.shared is True
    assert result.status == "SHARED_DEPENDENCIES_FOUND"
    assert result.shared_dependencies == (
        DependencyNode("requests", "2.32.0"),
    )


def test_non_shared_dependencies():
    result = detect_shared_dependencies([
        [Dependency("requests", "2.32.0")],
        [Dependency("flask", "3.0.0")],
    ])

    assert result.shared is False
    assert result.status == "NO_SHARED_DEPENDENCIES"
    assert result.shared_dependencies == ()


def test_multiple_shared_dependencies():
    result = detect_shared_dependencies([
        [Dependency("zlib", "1.0.0"), Dependency("requests", "2.0.0")],
        [Dependency("requests", "2.0.0"), Dependency("zlib", "1.0.0")],
    ])

    assert result.shared_dependencies == (
        DependencyNode("requests", "2.0.0"),
        DependencyNode("zlib", "1.0.0"),
    )


def test_same_dependency_twice_in_one_group_is_not_shared():
    result = detect_shared_dependencies([
        [Dependency("requests", "2.0.0"), Dependency("requests", "2.0.0")],
        [Dependency("flask", "3.0.0")],
    ])

    assert result.shared is False


def test_different_versions_are_not_the_same_dependency():
    result = detect_shared_dependencies([
        [Dependency("requests", "2.0.0")],
        [Dependency("requests", "3.0.0")],
    ])

    assert result.shared is False


def test_three_groups():
    result = detect_shared_dependencies([
        [Dependency("requests", "2.0.0")],
        [Dependency("requests", "2.0.0")],
        [Dependency("requests", "2.0.0")],
    ])

    assert result.shared is True
    assert result.shared_dependencies == (
        DependencyNode("requests", "2.0.0"),
    )


def test_empty_groups():
    result = detect_shared_dependencies([])

    assert result.shared is False
    assert result.status == "NO_DEPENDENCY_GROUPS"


def test_none():
    result = detect_shared_dependencies(None)

    assert result.shared is False
    assert result.status == "DEPENDENCY_GROUPS_IS_NONE"


def test_string_input_rejected():
    result = detect_shared_dependencies("requests")

    assert result.shared is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_GROUPS"


def test_invalid_group_rejected():
    result = detect_shared_dependencies([123])

    assert result.shared is False
    assert result.status == "INVALID_DEPENDENCY_GROUP"


def test_invalid_dependency_rejected():
    result = detect_shared_dependencies([[object()]])

    assert result.shared is False
    assert result.status == "INVALID_DEPENDENCY"


def test_invalid_name_rejected():
    result = detect_shared_dependencies([
        [Dependency("", "1.0.0")],
        [Dependency("", "1.0.0")],
    ])

    assert result.shared is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_version_rejected():
    result = detect_shared_dependencies([
        [Dependency("requests", 123)],
        [Dependency("requests", 123)],
    ])

    assert result.shared is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_name_whitespace_is_normalized():
    result = detect_shared_dependencies([
        [Dependency(" requests ", "2.0.0")],
        [Dependency("requests", "2.0.0")],
    ])

    assert result.shared is True
    assert result.shared_dependencies == (
        DependencyNode("requests", "2.0.0"),
    )


def test_result_type():
    result = detect_shared_dependencies([
        [Dependency("requests", "2.0.0")],
        [Dependency("requests", "2.0.0")],
    ])

    assert isinstance(result, SharedDependencyResult)


def test_result_is_immutable():
    result = detect_shared_dependencies([
        [Dependency("requests", "2.0.0")],
        [Dependency("requests", "2.0.0")],
    ])

    try:
        result.shared = False
        assert False
    except AttributeError:
        pass


def test_deterministic_sorting():
    result = detect_shared_dependencies([
        [
            Dependency("zlib", "1.0.0"),
            Dependency("requests", "2.0.0"),
            Dependency("flask", "3.0.0"),
        ],
        [
            Dependency("flask", "3.0.0"),
            Dependency("requests", "2.0.0"),
            Dependency("zlib", "1.0.0"),
        ],
    ])

    assert [d.name for d in result.shared_dependencies] == [
        "flask",
        "requests",
        "zlib",
    ]
