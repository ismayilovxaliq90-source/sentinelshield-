from dataclasses import dataclass

from sentinelshield.affected_version_matching import (
    AffectedVersionMatch,
    AffectedVersionMatchingResult,
    match_affected_version,
    match_affected_versions,
)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str


@dataclass(frozen=True)
class Vulnerability:
    package: str
    affected_versions: str


def test_exact_version_matches():
    result = match_affected_version(
        Dependency("requests", "2.32.0"),
        Vulnerability("requests", "2.32.0"),
    )

    assert result.matched is True
    assert result.status == "AFFECTED_VERSIONS_MATCHED"
    assert result.matches == (
        AffectedVersionMatch(
            "requests",
            "2.32.0",
            "2.32.0",
            True,
        ),
    )


def test_exact_version_does_not_match():
    result = match_affected_version(
        Dependency("requests", "2.32.1"),
        Vulnerability("requests", "2.32.0"),
    )

    assert result.matched is False
    assert result.status == "NO_AFFECTED_VERSIONS"


def test_greater_equal_constraint_matches():
    result = match_affected_version(
        Dependency("requests", "2.32.1"),
        Vulnerability("requests", ">=2.32.0"),
    )

    assert result.matched is True


def test_less_than_constraint_matches():
    result = match_affected_version(
        Dependency("requests", "2.31.0"),
        Vulnerability("requests", "<2.32.0"),
    )

    assert result.matched is True


def test_less_than_constraint_rejects_boundary():
    result = match_affected_version(
        Dependency("requests", "2.32.0"),
        Vulnerability("requests", "<2.32.0"),
    )

    assert result.matched is False


def test_range_constraint_matches():
    result = match_affected_version(
        Dependency("requests", "2.5.0"),
        Vulnerability("requests", ">=2.0,<3.0"),
    )

    assert result.matched is True


def test_range_constraint_rejects_outside_version():
    result = match_affected_version(
        Dependency("requests", "3.0.0"),
        Vulnerability("requests", ">=2.0,<3.0"),
    )

    assert result.matched is False


def test_caret_constraint_matches():
    result = match_affected_version(
        Dependency("requests", "1.5.0"),
        Vulnerability("requests", "^1.2.0"),
    )

    assert result.matched is True


def test_caret_constraint_rejects_next_major():
    result = match_affected_version(
        Dependency("requests", "2.0.0"),
        Vulnerability("requests", "^1.2.0"),
    )

    assert result.matched is False


def test_tilde_constraint_matches():
    result = match_affected_version(
        Dependency("requests", "1.2.5"),
        Vulnerability("requests", "~1.2.0"),
    )

    assert result.matched is True


def test_tilde_constraint_rejects_next_minor():
    result = match_affected_version(
        Dependency("requests", "1.3.0"),
        Vulnerability("requests", "~1.2.0"),
    )

    assert result.matched is False


def test_wildcard_constraint_matches():
    result = match_affected_version(
        Dependency("requests", "2.31.5"),
        Vulnerability("requests", "2.x"),
    )

    assert result.matched is True


def test_any_version_constraint_matches():
    result = match_affected_version(
        Dependency("requests", "99.1.2"),
        Vulnerability("requests", "*"),
    )

    assert result.matched is True


def test_package_name_is_case_insensitive():
    result = match_affected_version(
        Dependency("Requests", "2.32.0"),
        Vulnerability("REQUESTS", "2.32.0"),
    )

    assert result.matched is True


def test_package_name_separator_normalization():
    result = match_affected_version(
        Dependency("some_package", "1.2.3"),
        Vulnerability("some-package", "1.2.3"),
    )

    assert result.matched is True


def test_unrelated_package_does_not_match():
    result = match_affected_version(
        Dependency("requests", "2.32.0"),
        Vulnerability("flask", "2.32.0"),
    )

    assert result.matched is False


def test_multiple_matches_are_returned():
    result = match_affected_versions(
        [
            Dependency("requests", "2.31.0"),
            Dependency("flask", "2.0.0"),
        ],
        [
            Vulnerability("requests", "<2.32.0"),
            Vulnerability("flask", ">=1.0"),
        ],
    )

    assert len(result.matches) == 2
    assert {m.dependency_name for m in result.matches} == {
        "requests",
        "flask",
    }


def test_dict_inputs_are_supported():
    result = match_affected_versions(
        [{"name": "requests", "version": "2.32.0"}],
        [{"package": "requests", "affected_versions": "2.32.0"}],
    )

    assert result.matched is True


def test_tuple_inputs_are_supported():
    result = match_affected_versions(
        [("requests", "2.32.0")],
        [("requests", "2.32.0")],
    )

    assert result.matched is True


def test_none_dependencies():
    result = match_affected_versions(None, [])

    assert result.matched is False
    assert result.status == "DEPENDENCIES_IS_NONE"


def test_none_vulnerabilities():
    result = match_affected_versions([], None)

    assert result.matched is False
    assert result.status == "VULNERABILITIES_IS_NONE"


def test_invalid_dependency_collection():
    result = match_affected_versions(123, [])

    assert result.matched is False
    assert result.status == "UNSUPPORTED_DEPENDENCY_COLLECTION"


def test_invalid_vulnerability_collection():
    result = match_affected_versions([], 123)

    assert result.matched is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_invalid_dependency_name():
    result = match_affected_versions(
        [object()],
        [],
    )

    assert result.status == "INVALID_DEPENDENCY_NAME"


def test_invalid_dependency_version():
    result = match_affected_versions(
        [{"name": "requests", "version": "invalid"}],
        [],
    )

    assert result.status == "INVALID_DEPENDENCY_VERSION"


def test_invalid_vulnerability_package():
    result = match_affected_versions(
        [("requests", "2.32.0")],
        [object()],
    )

    assert result.status == "INVALID_VULNERABILITY_PACKAGE"


def test_invalid_constraint():
    result = match_affected_versions(
        [("requests", "2.32.0")],
        [("requests", "")],
    )

    assert result.status == "INVALID_AFFECTED_VERSION_CONSTRAINT"


def test_empty_collections_are_valid():
    result = match_affected_versions([], [])

    assert result.matched is False
    assert result.status == "NO_AFFECTED_VERSIONS"
    assert result.matches == ()


def test_inputs_are_not_modified():
    dependencies = [
        ("requests", "2.32.0"),
    ]
    vulnerabilities = [
        ("requests", "2.32.0"),
    ]

    original_dependencies = list(dependencies)
    original_vulnerabilities = list(vulnerabilities)

    match_affected_versions(
        dependencies,
        vulnerabilities,
    )

    assert dependencies == original_dependencies
    assert vulnerabilities == original_vulnerabilities


def test_result_is_immutable():
    result = match_affected_version(
        ("requests", "2.32.0"),
        ("requests", "2.32.0"),
    )

    try:
        result.matched = False
        raise AssertionError("Result must be immutable")
    except AttributeError:
        pass


def test_match_is_immutable():
    match = AffectedVersionMatch(
        "requests",
        "2.32.0",
        "2.32.0",
        True,
    )

    try:
        match.affected = False
        raise AssertionError("Match must be immutable")
    except AttributeError:
        pass


def test_result_type():
    result = match_affected_version(
        ("requests", "2.32.0"),
        ("requests", "2.32.0"),
    )

    assert isinstance(
        result,
        AffectedVersionMatchingResult,
    )


def test_match_type():
    result = match_affected_version(
        ("requests", "2.32.0"),
        ("requests", "2.32.0"),
    )

    assert isinstance(
        result.matches[0],
        AffectedVersionMatch,
    )
