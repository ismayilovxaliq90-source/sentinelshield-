from pathlib import Path

import pytest

from sentinelshield.unexpected_dependency_change_detection import (
    ApprovedDependencyChange,
    DependencyState,
    UnexpectedDependencyChangeError,
    UnexpectedDependencyChangeRequest,
    detect_unexpected_dependency_changes,
    normalize_dependency_name,
    validate_change_result,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    return root


def test_normalize_dependency_name():
    assert normalize_dependency_name(" Requests ") == "requests"
    assert normalize_dependency_name("my package") == "my-package"


def test_empty_dependency_name_is_rejected():
    with pytest.raises(ValueError):
        DependencyState("", "1.0.0")


def test_duplicate_baseline_fails(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
            DependencyState("requests", "2.32.0"),
        ),
        current=(
            DependencyState("requests", "2.32.0"),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is False
    assert result.reason == "DUPLICATE_DEPENDENCY"
    assert result.duplicate_baseline == ("requests",)


def test_duplicate_current_fails(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
        ),
        current=(
            DependencyState("requests", "2.32.0"),
            DependencyState("requests", "2.32.0"),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is False
    assert result.reason == "DUPLICATE_DEPENDENCY"
    assert result.duplicate_current == ("requests",)


def test_unexpected_addition_fails(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
        ),
        current=(
            DependencyState("requests", "2.31.0"),
            DependencyState("urllib3", "2.2.2"),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is False
    assert result.reason == "UNEXPECTED_DEPENDENCY_ADDED"
    assert result.unexpected_added == ("urllib3",)


def test_approved_addition_passes(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
        ),
        current=(
            DependencyState("requests", "2.31.0"),
            DependencyState("urllib3", "2.2.2"),
        ),
        approved_changes=(
            ApprovedDependencyChange(
                name="urllib3",
                new_version="2.2.2",
                change_type="add",
            ),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is True
    assert result.reason == "DEPENDENCY_CHANGES_EXPECTED"
    assert result.unexpected_added == ()
    assert validate_change_result(result) is True


def test_unexpected_removal_fails(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
            DependencyState("urllib3", "2.2.2"),
        ),
        current=(
            DependencyState("requests", "2.31.0"),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is False
    assert result.reason == "UNEXPECTED_DEPENDENCY_REMOVED"
    assert result.unexpected_removed == ("urllib3",)


def test_approved_removal_passes(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
            DependencyState("urllib3", "2.2.2"),
        ),
        current=(
            DependencyState("requests", "2.31.0"),
        ),
        approved_changes=(
            ApprovedDependencyChange(
                name="urllib3",
                old_version="2.2.2",
                change_type="remove",
            ),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is True
    assert result.unexpected_removed == ()


def test_unexpected_version_change_fails(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
        ),
        current=(
            DependencyState("requests", "2.32.0"),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is False
    assert result.reason == "UNEXPECTED_DEPENDENCY_UPDATED"
    assert result.unexpected_updated == ("requests",)


def test_approved_version_change_passes(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
        ),
        current=(
            DependencyState("requests", "2.32.0"),
        ),
        approved_changes=(
            ApprovedDependencyChange(
                name="requests",
                old_version="2.31.0",
                new_version="2.32.0",
                change_type="update",
            ),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is True
    assert result.unexpected_updated == ()


def test_approved_wrong_version_fails(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
        ),
        current=(
            DependencyState("requests", "2.33.0"),
        ),
        approved_changes=(
            ApprovedDependencyChange(
                name="requests",
                old_version="2.31.0",
                new_version="2.32.0",
                change_type="update",
            ),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is False
    assert result.unexpected_updated == ("requests",)


def test_unchanged_dependencies_pass(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
            DependencyState("urllib3", "2.2.2"),
        ),
        current=(
            DependencyState("requests", "2.31.0"),
            DependencyState("urllib3", "2.2.2"),
        ),
    )

    result = detect_unexpected_dependency_changes(request)

    assert result.valid is True
    assert result.changes == ()
    assert result.reason == "DEPENDENCY_CHANGES_EXPECTED"


def test_invalid_repository_is_rejected(tmp_path):
    request = UnexpectedDependencyChangeRequest(
        repository_root=tmp_path / "missing",
        baseline=(),
        current=(),
    )

    with pytest.raises(UnexpectedDependencyChangeError):
        detect_unexpected_dependency_changes(request)


def test_serialization(tmp_path):
    root = make_repo(tmp_path)

    request = UnexpectedDependencyChangeRequest(
        repository_root=root,
        baseline=(
            DependencyState("requests", "2.31.0"),
        ),
        current=(
            DependencyState("requests", "2.32.0"),
        ),
        approved_changes=(
            ApprovedDependencyChange(
                name="requests",
                old_version="2.31.0",
                new_version="2.32.0",
                change_type="update",
            ),
        ),
    )

    result = detect_unexpected_dependency_changes(request)
    data = result.to_dict()

    assert data["valid"] is True
    assert data["changes"][0]["change_type"] == "update"
    assert '"valid": true' in result.to_json().lower()
