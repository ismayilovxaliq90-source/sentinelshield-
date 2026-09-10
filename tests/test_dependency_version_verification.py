from pathlib import Path

import pytest

from sentinelshield.dependency_version_verification import (
    DependencyVersionVerificationError,
    DependencyVersionVerificationRequest,
    ExpectedDependencyVersion,
    ResolvedDependencyVersion,
    is_valid_version,
    validate_verification_result,
    verify_dependency_versions,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    return root


def test_valid_semver():
    assert is_valid_version("1.2.3") is True
    assert is_valid_version("v1.2.3") is True
    assert is_valid_version("1.2.3-beta.1") is True
    assert is_valid_version("1.2.3+build.5") is True


@pytest.mark.parametrize(
    "version",
    [
        "",
        "1",
        "1.2",
        "abc",
        "1.x.3",
        "1.2.3.4",
    ],
)
def test_invalid_version(version):
    assert is_valid_version(version) is False


def test_missing_dependency(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion("requests", "2.32.0"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
            ExpectedDependencyVersion("urllib3", "2.2.2"),
        ),
        package_manager="pip",
    )

    result = verify_dependency_versions(request)

    assert result.valid is False
    assert result.reason == "DEPENDENCY_VERSION_MISSING"
    assert result.missing == ("urllib3",)


def test_version_mismatch(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion("requests", "2.31.0"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
        ),
    )

    result = verify_dependency_versions(request)

    assert result.valid is False
    assert result.reason == "DEPENDENCY_VERSION_MISMATCH"
    assert len(result.mismatches) == 1
    assert result.mismatches[0].actual_version == "2.31.0"


def test_unexpected_dependency(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion("requests", "2.32.0"),
            ResolvedDependencyVersion("urllib3", "2.2.2"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
        ),
    )

    result = verify_dependency_versions(request)

    assert result.valid is False
    assert result.reason == "UNEXPECTED_DEPENDENCY"
    assert result.unexpected == ("urllib3",)


def test_duplicate_resolved_dependency(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion("requests", "2.31.0"),
            ResolvedDependencyVersion("requests", "2.32.0"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
        ),
    )

    result = verify_dependency_versions(request)

    assert result.valid is False
    assert result.reason == "DUPLICATE_RESOLVED_DEPENDENCY"
    assert result.duplicates == ("requests",)


def test_duplicate_expected_dependency_is_rejected(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion("requests", "2.32.0"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
            ExpectedDependencyVersion("REQUESTS", "2.32.0"),
        ),
    )

    with pytest.raises(DependencyVersionVerificationError):
        verify_dependency_versions(request)


def test_successful_verification(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion("requests", "2.32.0"),
            ResolvedDependencyVersion("urllib3", "2.2.2"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
            ExpectedDependencyVersion("urllib3", "2.2.2"),
        ),
        package_manager="pip",
    )

    result = verify_dependency_versions(request)

    assert result.valid is True
    assert result.reason == "DEPENDENCY_VERSIONS_VERIFIED"
    assert result.verified == ("requests", "urllib3")
    assert validate_verification_result(result) is True


def test_dependency_name_normalization(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion(" Requests ", "2.32.0"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
        ),
    )

    result = verify_dependency_versions(request)

    assert result.valid is True


def test_invalid_repository(tmp_path):
    request = DependencyVersionVerificationRequest(
        repository_root=tmp_path / "missing",
        resolved_dependencies=(),
        expected_dependencies=(),
    )

    with pytest.raises(DependencyVersionVerificationError):
        verify_dependency_versions(request)


def test_serialization(tmp_path):
    root = make_repo(tmp_path)

    request = DependencyVersionVerificationRequest(
        repository_root=root,
        resolved_dependencies=(
            ResolvedDependencyVersion("requests", "2.32.0"),
        ),
        expected_dependencies=(
            ExpectedDependencyVersion("requests", "2.32.0"),
        ),
    )

    result = verify_dependency_versions(request)
    data = result.to_dict()

    assert data["valid"] is True
    assert data["reason"] == "DEPENDENCY_VERSIONS_VERIFIED"
    assert '"valid": true' in result.to_json().lower()
