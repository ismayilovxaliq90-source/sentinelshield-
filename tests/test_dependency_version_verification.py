from pathlib import Path

import pytest

from sentinelshield.dependency_version_verification import (
    ActualDependency,
    DependencyVersionMismatch,
    DependencyVersionVerificationError,
    ExpectedDependency,
    DependencyVersionVerificationResult,
    normalize_version,
    validate_manifest_path,
    validate_verification_result,
    verify_dependency_versions,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "package.json").write_text(
        '{"name":"fixture","version":"1.0.0"}',
        encoding="utf-8",
    )
    return root


def test_version_normalization():
    assert normalize_version(" 1.2.3 ") == "1.2.3"
    assert normalize_version("v1.2.3") == "1.2.3"


def test_invalid_version_rejected():
    with pytest.raises(DependencyVersionVerificationError):
        normalize_version("not-a-version")


def test_exact_version_match():
    result = verify_dependency_versions(
        manager="npm",
        expected=(
            ExpectedDependency("is-number", "7.0.0"),
        ),
        actual=(
            ActualDependency("is-number", "7.0.0"),
        ),
    )

    assert result.success is True
    assert result.missing == ()
    assert result.unexpected == ()
    assert result.mismatches == ()
    assert len(result.verified) == 1


def test_version_mismatch_detected():
    result = verify_dependency_versions(
        manager="npm",
        expected=(
            ExpectedDependency("is-number", "7.0.0"),
        ),
        actual=(
            ActualDependency("is-number", "6.0.0"),
        ),
    )

    assert result.success is False
    assert result.mismatches == (
        DependencyVersionMismatch(
            name="is-number",
            expected=("7.0.0",),
            actual=("6.0.0",),
        ),
    )


def test_missing_dependency_detected():
    result = verify_dependency_versions(
        manager="npm",
        expected=(
            ExpectedDependency("is-number", "7.0.0"),
        ),
        actual=(),
    )

    assert result.success is False
    assert result.missing == ("is-number",)


def test_unexpected_dependency_detected():
    result = verify_dependency_versions(
        manager="npm",
        expected=(),
        actual=(
            ActualDependency("is-number", "7.0.0"),
        ),
    )

    assert result.success is False
    assert result.unexpected == ("is-number",)


def test_multiple_versions_are_detected():
    result = verify_dependency_versions(
        manager="npm",
        expected=(
            ExpectedDependency("foo", "1.0.0"),
        ),
        actual=(
            ActualDependency("foo", "1.0.0"),
            ActualDependency("foo", "2.0.0"),
        ),
    )

    assert result.success is True
    assert result.duplicate_versions["foo"] == (
        "1.0.0",
        "2.0.0",
    )


def test_duplicate_versions_with_no_expected_match_fail():
    result = verify_dependency_versions(
        manager="npm",
        expected=(
            ExpectedDependency("foo", "3.0.0"),
        ),
        actual=(
            ActualDependency("foo", "1.0.0"),
            ActualDependency("foo", "2.0.0"),
        ),
    )

    assert result.success is False
    assert "DEPENDENCY_VERSION_MISMATCH" in result.errors


def test_manager_is_normalized():
    result = verify_dependency_versions(
        manager=" NPM ",
        expected=(
            ExpectedDependency("foo", "1.0.0"),
        ),
        actual=(
            ActualDependency("foo", "1.0.0"),
        ),
    )

    assert result.manager == "npm"


def test_unknown_manager_rejected():
    with pytest.raises(DependencyVersionVerificationError):
        verify_dependency_versions(
            manager="unknown",
            expected=(),
            actual=(),
        )


def test_manifest_must_be_inside_repository(tmp_path):
    root = make_repo(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(DependencyVersionVerificationError):
        validate_manifest_path(root, outside)


def test_manifest_symlink_rejected(tmp_path):
    root = make_repo(tmp_path)
    real = root / "real.json"
    real.write_text("{}", encoding="utf-8")

    manifest = root / "link.json"
    manifest.symlink_to(real)

    with pytest.raises(DependencyVersionVerificationError):
        validate_manifest_path(root, manifest)


def test_result_validation():
    result = DependencyVersionVerificationResult(
        success=True,
        manager="npm",
        verified=(
            ActualDependency(
                name="foo",
                version="1.0.0",
            ),
        ),
        missing=(),
        unexpected=(),
        mismatches=(),
        duplicate_versions={},
        errors=(),
    )

    assert validate_verification_result(result) is True


def test_result_serialization():
    result = verify_dependency_versions(
        manager="npm",
        expected=(
            ExpectedDependency("foo", "1.0.0"),
        ),
        actual=(
            ActualDependency("foo", "1.0.0"),
        ),
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["manager"] == "npm"
    assert data["verified"][0]["name"] == "foo"
    assert data["verified"][0]["version"] == "1.0.0"


def test_empty_expected_and_actual_is_valid():
    result = verify_dependency_versions(
        manager="npm",
        expected=(),
        actual=(),
    )

    assert result.success is True
    assert validate_verification_result(result) is True
