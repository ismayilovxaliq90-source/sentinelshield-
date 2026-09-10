from pathlib import Path

import pytest

from sentinelshield.resolution_result_validation import (
    ExpectedDependency,
    ResolutionResult,
    ResolutionValidationError,
    ResolutionValidationRequest,
    ResolvedDependency,
    detect_duplicates,
    validate_resolution_result,
    version_satisfies,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    return root


def test_repository_root_must_exist(tmp_path: Path):
    result = ResolutionResult(
        success=True,
        exit_code=0,
        timed_out=False,
    )

    request = ResolutionValidationRequest(
        repository_root=tmp_path / "missing",
        result=result,
    )

    with pytest.raises(ResolutionValidationError):
        validate_resolution_result(request)


def test_failed_resolution_is_invalid(tmp_path: Path):
    root = make_repo(tmp_path)

    result = ResolutionResult(
        success=False,
        exit_code=1,
        timed_out=False,
    )

    request = ResolutionValidationRequest(
        repository_root=root,
        result=result,
    )

    validation = validate_resolution_result(request)

    assert validation.valid is False
    assert validation.reason == "RESOLUTION_FAILED"


def test_timeout_is_invalid(tmp_path: Path):
    root = make_repo(tmp_path)

    result = ResolutionResult(
        success=False,
        exit_code=None,
        timed_out=True,
    )

    request = ResolutionValidationRequest(
        repository_root=root,
        result=result,
    )

    validation = validate_resolution_result(request)

    assert validation.valid is False
    assert validation.reason == "RESOLUTION_TIMEOUT"


def test_non_zero_exit_code_is_invalid(tmp_path: Path):
    root = make_repo(tmp_path)

    result = ResolutionResult(
        success=True,
        exit_code=2,
        timed_out=False,
    )

    request = ResolutionValidationRequest(
        repository_root=root,
        result=result,
    )

    validation = validate_resolution_result(request)

    assert validation.valid is False
    assert validation.reason == "NON_ZERO_EXIT_CODE"


def test_missing_dependency_is_detected(tmp_path: Path):
    root = make_repo(tmp_path)

    result = ResolutionResult(
        success=True,
        exit_code=0,
        timed_out=False,
        dependencies=(
            ResolvedDependency("requests", "2.32.0"),
        ),
    )

    request = ResolutionValidationRequest(
        repository_root=root,
        result=result,
        expected_dependencies=(
            ExpectedDependency("requests", ">=2.0"),
            ExpectedDependency("urllib3", ">=2.0"),
        ),
    )

    validation = validate_resolution_result(request)

    assert validation.valid is False
    assert validation.reason == "MISSING_DEPENDENCIES"
    assert validation.missing_dependencies == ("urllib3",)


def test_version_mismatch_is_detected(tmp_path: Path):
    root = make_repo(tmp_path)

    result = ResolutionResult(
        success=True,
        exit_code=0,
        timed_out=False,
        dependencies=(
            ResolvedDependency("requests", "1.0.0"),
        ),
    )

    request = ResolutionValidationRequest(
        repository_root=root,
        result=result,
        expected_dependencies=(
            ExpectedDependency("requests", ">=2.0"),
        ),
    )

    validation = validate_resolution_result(request)

    assert validation.valid is False
    assert validation.reason == "VERSION_MISMATCH"


def test_duplicate_dependency_is_detected():
    dependencies = (
        ResolvedDependency("requests", "2.31.0"),
        ResolvedDependency("requests", "2.32.0"),
    )

    assert detect_duplicates(dependencies) == ("requests",)


def test_successful_resolution_passes(tmp_path: Path):
    root = make_repo(tmp_path)

    result = ResolutionResult(
        success=True,
        exit_code=0,
        timed_out=False,
        dependencies=(
            ResolvedDependency("requests", "2.32.0", direct=True),
            ResolvedDependency("urllib3", "2.2.2"),
        ),
    )

    request = ResolutionValidationRequest(
        repository_root=root,
        result=result,
        expected_dependencies=(
            ExpectedDependency("requests", ">=2.0"),
            ExpectedDependency("urllib3", "^2.0"),
        ),
    )

    validation = validate_resolution_result(request)

    assert validation.valid is True
    assert validation.reason == "RESOLUTION_VALID"
    assert validation.missing_dependencies == ()
    assert validation.version_mismatches == ()
    assert validation.duplicate_dependencies == ()


@pytest.mark.parametrize(
    ("version", "constraint", "expected"),
    [
        ("2.32.0", ">=2.0", True),
        ("2.32.0", "^2.0", True),
        ("2.32.0", "~2.32", True),
        ("1.9.0", ">=2.0", False),
        ("3.0.0", "^2.0", False),
        ("2.31.0", "~2.32", False),
        ("2.0.0", "2.0.0", True),
        ("2.0.1", "2.0.0", False),
        ("2.0.1", "*", True),
    ],
)
def test_version_satisfies(version, constraint, expected):
    assert version_satisfies(version, constraint) is expected


def test_serialization(tmp_path: Path):
    root = make_repo(tmp_path)

    result = ResolutionResult(
        success=True,
        exit_code=0,
        timed_out=False,
        dependencies=(
            ResolvedDependency("requests", "2.32.0"),
        ),
    )

    request = ResolutionValidationRequest(
        repository_root=root,
        result=result,
        expected_dependencies=(
            ExpectedDependency("requests", ">=2.0"),
        ),
    )

    validation = validate_resolution_result(request)

    data = validation.to_dict()

    assert data["valid"] is True
    assert data["reason"] == "RESOLUTION_VALID"
    assert '"valid": true' in validation.to_json().lower()
