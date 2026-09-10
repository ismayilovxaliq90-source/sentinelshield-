from pathlib import Path
import shutil
import subprocess

import pytest

from sentinelshield.existing_change_protection import (
    ExistingChangeProtectionError,
    capture_existing_change_protection,
    validate_existing_change_protection,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ("git", *args),
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")
    _git(repo, "config", "user.email", "task183@example.invalid")
    _git(repo, "config", "user.name", "Task 183")

    tracked = repo / "tracked.txt"
    tracked.write_text("original")

    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "initial")

    return repo


def test_clean_repository_has_no_protected_changes(tmp_path):
    repo = _init_repo(tmp_path)

    protection = capture_existing_change_protection(repo)

    assert protection.repository_root == str(repo.resolve())
    assert protection.changes == ()

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is True
    assert result.violations == ()


def test_protected_modified_file_is_detected(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    protection = capture_existing_change_protection(repo)

    tracked.write_text("changed again")

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert any(
        violation.startswith(
            "PROTECTED_CONTENT_CHANGED:tracked.txt"
        )
        for violation in result.violations
    )


def test_protected_file_deletion_fails(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    protection = capture_existing_change_protection(repo)

    tracked.unlink()

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert (
        "PROTECTED_CHANGE_MISSING:tracked.txt"
        in result.violations
    )


def test_protected_file_rename_is_detected(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    protection = capture_existing_change_protection(repo)

    renamed = repo / "renamed.txt"
    tracked.rename(renamed)

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert any(
        violation.startswith(
            "PROTECTED_CHANGE_MISSING:tracked.txt"
        )
        for violation in result.violations
    )


def test_unrelated_new_file_does_not_break_protection(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    protection = capture_existing_change_protection(repo)

    unrelated = repo / "new-file.txt"
    unrelated.write_text("new remediation file")

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is True
    assert result.violations == ()


def test_existing_untracked_file_is_protected(tmp_path):
    repo = _init_repo(tmp_path)

    untracked = repo / "user.txt"
    untracked.write_text("user data")

    protection = capture_existing_change_protection(repo)

    untracked.write_text("modified user data")

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert any(
        violation.startswith(
            "PROTECTED_CONTENT_CHANGED:user.txt"
        )
        for violation in result.violations
    )


def test_missing_repository_is_reported(tmp_path):
    repo = _init_repo(tmp_path)

    protection = capture_existing_change_protection(repo)

    # The old test used repo.rmdir(), but the repository is not empty.
    # Remove the complete temporary repository safely instead.
    shutil.rmtree(repo)

    result = validate_existing_change_protection(protection)

    assert result.valid is False
    assert result.protected is False
    assert result.violations == (
        "REPOSITORY_ROOT_MISSING",
    )


@pytest.mark.parametrize(
    "timeout",
    [0, -1],
)
def test_invalid_timeout_is_rejected(tmp_path, timeout):
    repo = _init_repo(tmp_path)

    with pytest.raises(ExistingChangeProtectionError):
        capture_existing_change_protection(
            repo,
            timeout=timeout,
        )


def test_invalid_protection_object_is_rejected(tmp_path):
    _init_repo(tmp_path)

    with pytest.raises(ExistingChangeProtectionError):
        validate_existing_change_protection(object())


def test_protected_symlink_change_is_detected(tmp_path):
    repo = _init_repo(tmp_path)

    target_a = repo / "target-a.txt"
    target_b = repo / "target-b.txt"

    target_a.write_text("A")
    target_b.write_text("B")

    link = repo / "link.txt"
    link.symlink_to(target_a.name)

    _git(
        repo,
        "add",
        "target-a.txt",
        "target-b.txt",
        "link.txt",
    )
    _git(repo, "commit", "-m", "add symlink")

    protection = capture_existing_change_protection(repo)

    # The symlink is clean at capture time, but Task 183 must
    # still protect it because it is a tracked symlink.
    link.unlink()
    link.symlink_to(target_b.name)

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert any(
        violation.startswith(
            "PROTECTED_CONTENT_CHANGED:link.txt"
        )
        for violation in result.violations
    )
