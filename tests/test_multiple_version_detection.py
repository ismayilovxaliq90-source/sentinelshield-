from sentinelshield.multiple_version_detection import (
    MultipleVersion,
    MultipleVersionDetectionResult,
    detect_multiple_versions,
)


class InputDependency:
    def __init__(self, name, version=None):
        self.name = name
        self.version = version


def test_detects_multiple_versions():
    result = detect_multiple_versions(
        [
            InputDependency("requests", "2.31.0"),
            InputDependency("requests", "2.32.0"),
        ]
    )

    assert result.detected is True
    assert result.status == "MULTIPLE_VERSIONS_DETECTED"
    assert result.dependencies == (
        MultipleVersion(
            "requests",
            ("2.31.0", "2.32.0"),
        ),
    )


def test_single_version_is_not_reported():
    result = detect_multiple_versions(
        [
            InputDependency("requests", "2.32.0"),
            InputDependency("requests", "2.32.0"),
        ]
    )

    assert result.detected is False
    assert result.status == "NO_MULTIPLE_VERSIONS"
    assert result.dependencies == ()


def test_multiple_packages():
    result = detect_multiple_versions(
        [
            InputDependency("zlib", "1.0"),
            InputDependency("zlib", "2.0"),
            InputDependency("axios", "1.0"),
            InputDependency("axios", "2.0"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "axios",
        "zlib",
    ]


def test_versions_are_sorted():
    result = detect_multiple_versions(
        [
            InputDependency("pkg", "3.0"),
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "2.0"),
        ]
    )

    assert result.dependencies[0].versions == (
        "1.0",
        "2.0",
        "3.0",
    )


def test_packages_are_sorted():
    result = detect_multiple_versions(
        [
            InputDependency("z", "1"),
            InputDependency("z", "2"),
            InputDependency("a", "1"),
            InputDependency("a", "2"),
        ]
    )

    assert [item.name for item in result.dependencies] == [
        "a",
        "z",
    ]


def test_none_version_is_ignored():
    result = detect_multiple_versions(
        [
            InputDependency("pkg", None),
            InputDependency("pkg", "1.0"),
        ]
    )

    assert result.detected is False


def test_empty_version_is_ignored():
    result = detect_multiple_versions(
        [
            InputDependency("pkg", ""),
            InputDependency("pkg", "1.0"),
        ]
    )

    assert result.detected is False


def test_none_dependencies():
    result = detect_multiple_versions(None)

    assert result.detected is False
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_string_dependencies():
    result = detect_multiple_versions("requests")

    assert result.detected is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_non_iterable_dependencies():
    result = detect_multiple_versions(123)

    assert result.detected is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_name():
    result = detect_multiple_versions(
        [InputDependency("", "1.0")]
    )

    assert result.detected is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_version():
    result = detect_multiple_versions(
        [InputDependency("pkg", 123)]
    )

    assert result.detected is False
    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_dict_dependencies():
    result = detect_multiple_versions(
        [
            {"name": "pkg", "version": "1.0"},
            {"name": "pkg", "version": "2.0"},
        ]
    )

    assert result.detected is True
    assert result.dependencies[0].name == "pkg"


def test_whitespace_is_normalized():
    result = detect_multiple_versions(
        [
            InputDependency(" pkg ", " 1.0 "),
            InputDependency("pkg", "2.0"),
        ]
    )

    assert result.dependencies == (
        MultipleVersion("pkg", ("1.0", "2.0")),
    )


def test_duplicate_versions_are_collapsed():
    result = detect_multiple_versions(
        [
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "2.0"),
        ]
    )

    assert result.dependencies[0].versions == (
        "1.0",
        "2.0",
    )


def test_empty_inventory():
    result = detect_multiple_versions([])

    assert isinstance(result, MultipleVersionDetectionResult)
    assert result.detected is False
    assert result.status == "NO_MULTIPLE_VERSIONS"
    assert result.dependencies == ()


def test_input_is_not_modified():
    dependencies = [
        InputDependency("pkg", "1.0"),
        InputDependency("pkg", "2.0"),
    ]
    original = list(dependencies)

    detect_multiple_versions(dependencies)

    assert dependencies == original


def test_result_is_immutable():
    result = detect_multiple_versions(
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


def test_multiple_version_is_immutable():
    result = detect_multiple_versions(
        [
            InputDependency("pkg", "1.0"),
            InputDependency("pkg", "2.0"),
        ]
    )

    try:
        result.dependencies[0].name = "changed"
    except AttributeError:
        pass
    else:
        raise AssertionError("MultipleVersion must be immutable")
