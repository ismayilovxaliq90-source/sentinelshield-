from pathlib import Path
import subprocess

import pytest

from sentinelshield.remediation_scope_enforcement import (
    RemediationScopeError,
    enforce_remediation_scope,
    normalize_allowed_scope,
    validate_remediation_scope_result,
)


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        ["git", "init"],
        cwd=path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=path,
        check=True,
    )

    subprocess.run(
        ["git", "config", "user.name", "SentinelShield Test"],
        cwd=path,
        check=True,
    )

    return path


def commit_all(repo: Path) -> None:
    subprocess.run(
        ["git", "add", "."],
        cwd=repo,
        check=True,
    )

    subprocess.run(
        ["git", "commit", "-m", "baseline"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_clean_repository_passes(tmp_path):
    repo = init_repo(tmp_path / "repo")
    target = repo / "package.json"
    target.write_text("{}", encoding="utf-8")
    commit_all(repo)

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    assert result.valid is True
    assert result.in_scope is True
    assert result.out_of_scope_changes == ()
    assert result.passed is True
    assert validate_remediation_scope_result(result) is True


def test_allowed_file_change_passes(tmp_path):
    repo = init_repo(tmp_path / "repo")
    target = repo / "package.json"
    target.write_text('{"version":1}', encoding="utf-8")
    commit_all(repo)

    target.write_text('{"version":2}', encoding="utf-8")

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    assert result.passed is True
    assert result.out_of_scope_changes == ()
    assert len(result.allowed_changes) == 1


def test_nested_allowed_path_passes(tmp_path):
    repo = init_repo(tmp_path / "repo")
    target = repo / "service" / "package.json"
    target.parent.mkdir(parents=True)
    target.write_text("{}", encoding="utf-8")
    commit_all(repo)

    target.write_text('{"changed":true}', encoding="utf-8")

    result = enforce_remediation_scope(
        repo,
        ["service"],
    )

    assert result.passed is True
    assert result.allowed_changes[0].path == "service/package.json"


def test_unexpected_file_fails(tmp_path):
    repo = init_repo(tmp_path / "repo")
    tracked = repo / "package.json"
    tracked.write_text("{}", encoding="utf-8")
    commit_all(repo)

    unexpected = repo / "README.md"
    unexpected.write_text("unexpected", encoding="utf-8")

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    assert result.passed is False
    assert len(result.out_of_scope_changes) == 1
    assert result.out_of_scope_changes[0].path == "README.md"
    assert validate_remediation_scope_result(result) is False


def test_empty_scope_only_allows_clean_repository(tmp_path):
    repo = init_repo(tmp_path / "repo")
    tracked = repo / "package.json"
    tracked.write_text("{}", encoding="utf-8")
    commit_all(repo)

    result = enforce_remediation_scope(repo, [])

    assert result.passed is True

    tracked.write_text('{"changed":true}', encoding="utf-8")

    result = enforce_remediation_scope(repo, [])

    assert result.passed is False
    assert result.out_of_scope_changes


def test_absolute_scope_path_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    with pytest.raises(RemediationScopeError):
        normalize_allowed_scope(
            repo,
            ["/tmp/outside"],
        )


def test_parent_traversal_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    with pytest.raises(RemediationScopeError):
        normalize_allowed_scope(
            repo,
            ["../outside"],
        )


def test_empty_scope_path_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    with pytest.raises(RemediationScopeError):
        normalize_allowed_scope(
            repo,
            ["   "],
        )


def test_none_scope_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    with pytest.raises(RemediationScopeError):
        normalize_allowed_scope(
            repo,
            None,
        )


def test_missing_repository_rejected(tmp_path):
    with pytest.raises(RemediationScopeError):
        enforce_remediation_scope(
            tmp_path / "missing",
            ["package.json"],
        )


def test_non_git_repository_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(RemediationScopeError):
        enforce_remediation_scope(
            repo,
            ["package.json"],
        )


def test_serialization(tmp_path):
    repo = init_repo(tmp_path / "repo")
    target = repo / "package.json"
    target.write_text("{}", encoding="utf-8")
    commit_all(repo)

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    data = result.to_dict()

    assert data["valid"] is True
    assert data["passed"] is True
    assert data["out_of_scope_changes"] == []
