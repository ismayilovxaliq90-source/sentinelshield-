from pathlib import Path

import pytest

from sentinelshield.dependency_version_verification import (
    DependencyVersionMismatch,
    DependencyVersionVerificationError,
    DependencyVersionVerificationRequest,
    ExpectedDependencyVersion,
    ResolvedDependencyVersion,
    is_valid_version,
    normalize_name,
    validate_verification_result,
    verify_dependency_versions,
)


def make_request(tmp_path, expected, resolved):
    return DependencyVersionVerificationRequest(
        repository_root=tmp_path,
        expected=expected,
        resolved=resolved,
    )


def test_normalize_name():
    assert normalize_name(" Requests ") == "requests"
    assert normalize_name("My_Package") == "my-package"
    assert normalize_name("my.package") == "my-package"


def test_normalize_name_rejects_invalid_values():
    with pytest.raises(DependencyVersionVerificationError):
        normalize_name("")

    with pytest.raises(DependencyVersionVerificationError):
        normalize_name("   ")

    with pytest.raises(DependencyVersionVerificationError):
        normalize_name("bad\x00name")

    with pytest.raises(DependencyVersionVerificationError):
        normalize_name(123)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "version",
    [
        "1",
        "1.2",
        "1.2.3",
        "1.2.3.4",
        "1.2.3-alpha",
        "1.2.3+build.1",
        "1.2.3-alpha+build.1",
    ],
)
def test_valid_versions(version):
    assert is_valid_version(version) is True


@pytest.mark.parametrize(
    "version",
    [
        "",
        " ",
        "latest",
        "^1.2.3",
        "~1.2.3",
        "1.x",
        "v1.2.3",
    ],
)
def test_invalid_versions(version):
    assert is_valid_version(version) is False


def test_expected_dependency_requires_valid_version():
    with pytest.raises(DependencyVersionVerificationError):
        ExpectedDependencyVersion("requests", "latest")


def test_resolved_dependency_requires_valid_version():
    with pytest.raises(DependencyVersionVerificationError):
        ResolvedDependencyVersion("requests", "bad")


def test_all_versions_match(tmp_path):
    expected = [
        ExpectedDependencyVersion("requests", "2.32.4"),
        ExpectedDependencyVersion("urllib3", "2.5.0"),
    ]

    resolved = [
        ResolvedDependencyVersion("requests", "2.32.4"),
        ResolvedDependencyVersion("urllib3", "2.5.0"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    assert result.valid is True
    assert result.missing == []
    assert result.unexpected == []
    assert result.mismatches == []
    assert result.duplicates == []
    assert result.errors == []
    assert validate_verification_result(result) is True


def test_missing_dependency(tmp_path):
    expected = [
        ExpectedDependencyVersion("requests", "2.32.4"),
        ExpectedDependencyVersion("urllib3", "2.5.0"),
    ]

    resolved = [
        ResolvedDependencyVersion("requests", "2.32.4"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    assert result.valid is False
    assert result.missing == ["urllib3"]
    assert validate_verification_result(result) is False


def test_unexpected_dependency(tmp_path):
    expected = [
        ExpectedDependencyVersion("requests", "2.32.4"),
    ]

    resolved = [
        ResolvedDependencyVersion("requests", "2.32.4"),
        ResolvedDependencyVersion("urllib3", "2.5.0"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    assert result.valid is False
    assert result.unexpected == ["urllib3"]


def test_version_mismatch(tmp_path):
    expected = [
        ExpectedDependencyVersion("requests", "2.32.4"),
    ]

    resolved = [
        ResolvedDependencyVersion("requests", "2.31.0"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    assert result.valid is False
    assert result.mismatches == [
        DependencyVersionMismatch(
            name="requests",
            expected_version="2.32.4",
            actual_version="2.31.0",
        )
    ]


def test_duplicate_expected_dependency(tmp_path):
    expected = [
        ExpectedDependencyVersion("requests", "2.32.4"),
        ExpectedDependencyVersion("Requests", "2.32.4"),
    ]

    resolved = [
        ResolvedDependencyVersion("requests", "2.32.4"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    assert result.valid is False
    assert result.duplicates == ["requests"]


def test_duplicate_resolved_dependency(tmp_path):
    expected = [
        ExpectedDependencyVersion("requests", "2.32.4"),
    ]

    resolved = [
        ResolvedDependencyVersion("requests", "2.32.4"),
        ResolvedDependencyVersion("Requests", "2.32.4"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    assert result.valid is False
    assert result.duplicates == ["requests"]


def test_names_are_compared_normalized(tmp_path):
    expected = [
        ExpectedDependencyVersion("My_Package", "1.2.3"),
    ]

    resolved = [
        ResolvedDependencyVersion("my.package", "1.2.3"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    assert result.valid is True


def test_empty_dependency_sets_are_valid(tmp_path):
    result = verify_dependency_versions(
        make_request(tmp_path, [], [])
    )

    assert result.valid is True
    assert validate_verification_result(result) is True


def test_relative_repository_root_rejected(tmp_path):
    with pytest.raises(DependencyVersionVerificationError):
        DependencyVersionVerificationRequest(
            repository_root=Path("relative"),
            expected=[],
            resolved=[],
        )


def test_missing_repository_root_rejected(tmp_path):
    missing = tmp_path / "does-not-exist"

    request = make_request(
        missing,
        [],
        [],
    )

    with pytest.raises(DependencyVersionVerificationError):
        verify_dependency_versions(request)


def test_result_serialization(tmp_path):
    expected = [
        ExpectedDependencyVersion("requests", "2.32.4"),
    ]

    resolved = [
        ResolvedDependencyVersion("requests", "2.31.0"),
    ]

    result = verify_dependency_versions(
        make_request(tmp_path, expected, resolved)
    )

    payload = result.to_dict()

    assert payload["valid"] is False
    assert payload["repository_root"] == str(tmp_path.resolve())
    assert len(payload["mismatches"]) == 1

    json_text = result.to_json()

    assert '"valid": false' in json_text
    assert '"requests"' in json_text
