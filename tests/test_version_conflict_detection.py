from sentinelshield.version_conflict_detection import (
    VersionConflict,
    VersionConflictDetectionResult,
    detect_version_conflicts,
)


class InputDependency:
    def __init__(self, name, version=None):
        self.name = name
        self.version = version


def test_detects_version_conflict():
    result = detect_version_conflicts(
        [
            InputDependency("requests", "2.31.0"),
            InputDependency("requests", "2.32.0"),
        ]
    )

    assert result.detected is True
    assert result.status == "VERSION_CONFLICTS_DETECTED"
    assert result.conflicts == (
        VersionConflict(
            "requests",
            ("2.31.0", "2.32.0"),
        ),
    )


def test_same_version_is_not_conflict():
    result = detect_version_conflicts(
        [
            InputDependency("requests", "2.32.0"),
            InputDependency("requests", "2.32.0"),
        ]
    )

    assert result.detected is False
    assert result.status == "NO_VERSION_CONFLICTS"
    assert result.conflicts == ()


def test_multiple_conflicts():
    result = detect_version_conflicts(
        [
            InputDependency("zlib", "1.0"),
            InputDependency("zlib", "2.0"),
            InputDependency("axios", "1.0"),
            InputDependency("axios", "2.0"),
        ]
    )

    assert [item.name for item in result.conflicts] == [
        "axios",
        "zlib",
    ]


def test_versions_are_sorted():
    result = detect_version_conflicts(
        [
            InputDependency("pkg", "3.0"),
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "2.0"),
        ]
    )

    assert result.conflicts[0].versions == (
        "1.0",
        "2.0",
        "3.0",
    )


def test_none_version_is_ignored():
    result = detect_version_conflicts(
        [
            InputDependency("pkg", None),
            InputDependency("pkg", "1.0"),
        ]
    )

    assert result.detected is False


def test_empty_version_is_ignored():
    result = detect_version_conflicts(
        [
            InputDependency("pkg", ""),
            InputDependency("pkg", "1.0"),
        ]
    )

    assert result.detected is False


def test_none_dependencies():
    result = detect_version_conflicts(None)

    assert result.detected is False
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_string_dependencies():
    result = detect_version_conflicts("requests")

    assert result.detected is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_dependencies():
    result = detect_version_conflicts(123)

    assert result.detected is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_name():
    result = detect_version_conflicts(
        [InputDependency("", "1.0")]
    )

    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_version():
    result = detect_version_conflicts(
        [InputDependency("pkg", 123)]
    )

    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_dict_dependencies():
    result = detect_version_conflicts(
        [
            {"name": "pkg", "version": "1.0"},
            {"name": "pkg", "version": "2.0"},
        ]
    )

    assert result.detected is True


def test_whitespace_is_normalized():
    result = detect_version_conflicts(
        [
            InputDependency(" pkg ", " 1.0 "),
            InputDependency("pkg", "2.0"),
        ]
    )

    assert result.conflicts == (
        VersionConflict("pkg", ("1.0", "2.0")),
    )


def test_duplicate_versions_are_collapsed():
    result = detect_version_conflicts(
        [
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "2.0"),
        ]
    )

    assert result.conflicts[0].versions == (
        "1.0",
        "2.0",
    )


def test_empty_inventory():
    result = detect_version_conflicts([])

    assert isinstance(result, VersionConflictDetectionResult)
    assert result.detected is False
    assert result.status == "NO_VERSION_CONFLICTS"
    assert result.conflicts == ()


def test_input_is_not_modified():
    dependencies = [
        InputDependency("pkg", "1.0"),
        InputDependency("pkg", "2.0"),
    ]
    original = list(dependencies)

    detect_version_conflicts(dependencies)

    assert dependencies == original


def test_result_is_immutable():
    result = detect_version_conflicts(
        [
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "2.0"),
        ]
    )

    try:
        result.detected = False
    except AttributeError:
        pass
    else:
        raise AssertionError("Result must be immutable")


def test_conflict_is_immutable():
    result = detect_version_conflicts(
        [
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "2.0"),
        ]
    )

    try:
        result.conflicts[0].name = "changed"
    except AttributeError:
        pass
    else:
        raise AssertionError("VersionConflict must be immutable")
