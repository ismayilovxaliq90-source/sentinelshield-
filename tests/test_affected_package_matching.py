from dataclasses import dataclass

from sentinelshield.affected_package_matching import (
    AffectedPackageMatch,
    AffectedPackageMatchingResult,
    match_affected_package,
    match_affected_packages,
)


@dataclass(frozen=True)
class Dependency:
    name: str


@dataclass(frozen=True)
class Vulnerability:
    package: str


def test_matching_package_is_detected():
    result = match_affected_package(
        Dependency("requests"),
        Vulnerability("requests"),
    )

    assert result.matched is True
    assert result.status == "AFFECTED_PACKAGES_MATCHED"
    assert result.matches == (
        AffectedPackageMatch(
            "requests",
            "requests",
            True,
        ),
    )


def test_non_matching_package_is_not_detected():
    result = match_affected_package(
        Dependency("requests"),
        Vulnerability("flask"),
    )

    assert result.matched is False
    assert result.status == "NO_AFFECTED_PACKAGES"
    assert result.matches == ()


def test_matching_is_case_insensitive():
    result = match_affected_package(
        Dependency("Requests"),
        Vulnerability("REQUESTS"),
    )

    assert result.matched is True


def test_whitespace_is_normalized():
    result = match_affected_package(
        Dependency("  requests  "),
        Vulnerability(" requests "),
    )

    assert result.matched is True


def test_underscore_is_normalized():
    result = match_affected_package(
        Dependency("some_package"),
        Vulnerability("some-package"),
    )

    assert result.matched is True


def test_dot_is_normalized():
    result = match_affected_package(
        Dependency("some.package"),
        Vulnerability("some-package"),
    )

    assert result.matched is True


def test_multiple_matches_are_returned():
    result = match_affected_packages(
        [
            Dependency("requests"),
            Dependency("flask"),
            Dependency("django"),
        ],
        [
            Vulnerability("flask"),
            Vulnerability("django"),
        ],
    )

    assert result.matched is True
    assert [m.dependency_name for m in result.matches] == [
        "django",
        "flask",
    ]


def test_unmatched_dependencies_are_excluded():
    result = match_affected_packages(
        [Dependency("requests")],
        [Vulnerability("flask")],
    )

    assert result.matches == ()


def test_string_dependency_is_supported():
    result = match_affected_packages(
        ["requests"],
        ["requests"],
    )

    assert result.matched is True


def test_string_vulnerability_is_supported():
    result = match_affected_packages(
        ["requests"],
        "requests",
    )

    assert result.matched is True


def test_dict_dependency_is_supported():
    result = match_affected_packages(
        [{"name": "requests"}],
        [{"package": "requests"}],
    )

    assert result.matched is True


def test_dict_package_name_is_supported():
    result = match_affected_packages(
        [{"package_name": "requests"}],
        [{"package_name": "requests"}],
    )

    assert result.matched is True


def test_none_dependencies_are_rejected():
    result = match_affected_packages(None, ["requests"])

    assert result.matched is False
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_none_vulnerabilities_are_rejected():
    result = match_affected_packages(["requests"], None)

    assert result.matched is False
    assert result.status == "VULNERABILITIES_IS_NONE"


def test_invalid_dependency_collection_is_rejected():
    result = match_affected_packages(123, ["requests"])

    assert result.matched is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_vulnerability_collection_is_rejected():
    result = match_affected_packages(["requests"], 123)

    assert result.matched is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_invalid_dependency_name_is_rejected():
    result = match_affected_packages(
        [object()],
        ["requests"],
    )

    assert result.matched is False
    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_vulnerability_package_is_rejected():
    result = match_affected_packages(
        ["requests"],
        [object()],
    )

    assert result.matched is False
    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_empty_collections_are_valid():
    result = match_affected_packages([], [])

    assert result.matched is False
    assert result.status == "NO_AFFECTED_PACKAGES"
    assert result.matches == ()


def test_dependency_input_is_not_modified():
    dependencies = [
        Dependency("requests"),
        Dependency("flask"),
    ]
    original = list(dependencies)

    match_affected_packages(
        dependencies,
        ["requests"],
    )

    assert dependencies == original


def test_result_is_immutable():
    result = match_affected_package(
        "requests",
        "requests",
    )

    try:
        result.matched = False
        raise AssertionError("Result must be immutable")
    except AttributeError:
        pass


def test_match_is_immutable():
    match = AffectedPackageMatch(
        "requests",
        "requests",
        True,
    )

    try:
        match.matched = False
        raise AssertionError("Match must be immutable")
    except AttributeError:
        pass


def test_result_type_is_correct():
    result = match_affected_package(
        "requests",
        "requests",
    )

    assert isinstance(
        result,
        AffectedPackageMatchingResult,
    )


def test_match_type_is_correct():
    result = match_affected_package(
        "requests",
        "requests",
    )

    assert isinstance(
        result.matches[0],
        AffectedPackageMatch,
    )


def test_duplicate_dependency_names_are_deterministic():
    result = match_affected_packages(
        [
            Dependency("requests"),
            Dependency("requests"),
        ],
        ["requests"],
    )

    assert len(result.matches) == 2
    assert all(
        match.dependency_name == "requests"
        for match in result.matches
    )
