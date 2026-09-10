from pathlib import Path
import subprocess

import pytest

from sentinelshield.remediation_scope_enforcement import (
    RemediationScopeError,
    enforce_remediation_scope,
    normalize_approved_scope,
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


def commit_all(path: Path) -> None:
    subprocess.run(
        ["git", "add", "."],
        cwd=path,
        check=True,
    )

    subprocess.run(
        ["git", "commit", "-m", "baseline"],
        cwd=path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_clean_repository_passes(tmp_path):
    repo = init_repo(tmp_path / "repo")

    target = repo / "package.json"
    target.write_text('{"version": 1}\n', encoding="utf-8")
    commit_all(repo)

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    assert result.valid is True
    assert result.in_scope is True
    assert result.out_of_scope_changes == ()
    assert validate_remediation_scope_result(result) is True


def test_expected_file_change_is_in_scope(tmp_path):
    repo = init_repo(tmp_path / "repo")

    target = repo / "package.json"
    target.write_text('{"version": 1}\n', encoding="utf-8")
    commit_all(repo)

    target.write_text('{"version": 2}\n', encoding="utf-8")

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    assert result.in_scope is True
    assert len(result.accepted_changes) == 1
    assert result.accepted_changes[0].path == "package.json"
    assert result.accepted_changes[0].status == "M"


def test_nested_file_is_in_scope_when_directory_is_approved(tmp_path):
    repo = init_repo(tmp_path / "repo")

    directory = repo / "service"
    directory.mkdir()
    target = directory / "package-lock.json"
    target.write_text("baseline\n", encoding="utf-8")
    commit_all(repo)

    target.write_text("changed\n", encoding="utf-8")

    result = enforce_remediation_scope(
        repo,
        ["service"],
    )

    assert result.in_scope is True
    assert result.out_of_scope_changes == ()


def test_unexpected_file_fails_scope(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        '{"version": 1}\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text(
        "baseline\n",
        encoding="utf-8",
    )
    commit_all(repo)

    (repo / "package.json").write_text(
        '{"version": 2}\n",
        encoding="utf-8",
    )

    (repo / "README.md").write_text(
        "unexpected\n",
        encoding="utf-8",
    )

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    assert result.in_scope is False
    assert len(result.out_of_scope_changes) == 1
    assert result.out_of_scope_changes[0].path == "README.md"
    assert validate_remediation_scope_result(result) is False


def test_unexpected_new_file_fails(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    commit_all(repo)

    (repo / "unexpected.txt").write_text(
        "unexpected\n",
        encoding="utf-8",
    )

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    assert result.in_scope is False
    assert result.added_files == ("unexpected.txt",)


def test_unexpected_deleted_file_fails(tmp_path):
    repo = init_repo(tmp_path / "repo")

    target = repo / "package.json"
    target.write_text("{}\n", encoding="utf-8")
    commit_all(repo)

    target.unlink()

    result = enforce_remediation_scope(
        repo,
        ["src"],
    )

    assert result.in_scope is False
    assert result.deleted_files == ("package.json",)


def test_empty_scope_is_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    commit_all(repo)

    with pytest.raises(RemediationScopeError):
        normalize_approved_scope(repo, [])


def test_string_scope_container_is_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    commit_all(repo)

    with pytest.raises(RemediationScopeError):
        normalize_approved_scope(repo, "package.json")


def test_outside_repository_scope_is_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    commit_all(repo)

    outside = tmp_path / "outside.txt"

    with pytest.raises(RemediationScopeError):
        normalize_approved_scope(repo, [outside])


def test_null_character_is_rejected(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    commit_all(repo)

    with pytest.raises(RemediationScopeError):
        normalize_approved_scope(
            repo,
            ["package.json\x00evil"],
        )


def test_scope_normalization_is_deterministic(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (repo / "package-lock.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    commit_all(repo)

    result = normalize_approved_scope(
        repo,
        ["./package-lock.json", "package.json"],
    )

    assert result == (
        "package-lock.json",
        "package.json",
    )


def test_result_serialization(tmp_path):
    repo = init_repo(tmp_path / "repo")

    (repo / "package.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    commit_all(repo)

    (repo / "package.json").write_text(
        '{"changed": true}\n',
        encoding="utf-8",
    )

    result = enforce_remediation_scope(
        repo,
        ["package.json"],
    )

    data = result.to_dict()

    assert data["valid"] is True
    assert data["in_scope"] is True
    assert data["passed"] is True
    assert "package.json" in data["approved_scope"]
