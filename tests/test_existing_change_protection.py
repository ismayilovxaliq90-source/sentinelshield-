import subprocess

from sentinelshield.existing_change_protection import (
    ExistingChangeProtection,
    ProtectionValidationResult,
    capture_existing_change_protection,
    validate_existing_change_protection,
)


def _run_git(repo, *args):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )


def _init_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _run_git(repo, "init")

    tracked = repo / "tracked.txt"
    tracked.write_text("baseline")

    _run_git(repo, "add", "tracked.txt")

    _run_git(
        repo,
        "-c",
        "user.name=Task183",
        "-c",
        "user.email=task183@example.invalid",
        "commit",
        "-m",
        "baseline",
    )

    return repo


def test_clean_repository_has_no_protected_changes(tmp_path):
    repo = _init_repo(tmp_path)

    protection = capture_existing_change_protection(repo)

    assert protection.valid is True
    assert protection.changes == ()
    assert protection.reason == "NO_EXISTING_CHANGES"

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is True
    assert result.violations == ()
    assert result.reason == "NO_EXISTING_CHANGES_TO_PROTECT"


def test_existing_modified_file_is_captured_and_preserved(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    protection = capture_existing_change_protection(repo)

    assert protection.valid is True
    assert len(protection.changes) == 1
    assert protection.changes[0].path == "tracked.txt"
    assert protection.changes[0].status == " M"

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is True
    assert result.violations == ()


def test_protected_file_modification_fails(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    protection = capture_existing_change_protection(repo)

    tracked.write_text("remediation overwrote user change")

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert "PROTECTED_CONTENT_CHANGED:tracked.txt" in result.violations


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


def test_existing_untracked_file_is_protected(tmp_path):
    repo = _init_repo(tmp_path)

    new_file = repo / "user_change.txt"
    new_file.write_text("keep this")

    protection = capture_existing_change_protection(repo)

    assert protection.valid is True
    assert len(protection.changes) == 1
    assert protection.changes[0].path == "user_change.txt"
    assert protection.changes[0].status == "??"

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is True


def test_existing_untracked_file_content_change_fails(tmp_path):
    repo = _init_repo(tmp_path)

    new_file = repo / "user_change.txt"
    new_file.write_text("keep this")

    protection = capture_existing_change_protection(repo)

    new_file.write_text("changed")

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert (
        "PROTECTED_CONTENT_CHANGED:user_change.txt"
        in result.violations
    )


def test_new_unrelated_change_is_allowed(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    protection = capture_existing_change_protection(repo)

    unrelated = repo / "new_remediation_file.txt"
    unrelated.write_text("new remediation change")

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is True
    assert result.violations == ()


def test_staging_state_is_protected(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    _run_git(repo, "add", "tracked.txt")

    protection = capture_existing_change_protection(repo)

    tracked.write_text("changed again")

    result = validate_existing_change_protection(protection)

    assert result.valid is True
    assert result.protected is False
    assert any(
        violation.startswith(
            "PROTECTED_STATUS_CHANGED:tracked.txt"
        )
        for violation in result.violations
    ) or any(
        violation.startswith(
            "PROTECTED_CONTENT_CHANGED:tracked.txt"
        )
        for violation in result.violations
    )


def test_invalid_protection_state_fails_closed(tmp_path):
    protection = ExistingChangeProtection(
        repository_root=tmp_path,
        changes=(),
        valid=False,
        reason="TEST_INVALID",
    )

    result = validate_existing_change_protection(protection)

    assert result.valid is False
    assert result.protected is False
    assert result.reason == "INVALID_PROTECTION_STATE"


def test_validation_result_shape():
    result = ProtectionValidationResult(
        valid=True,
        protected=True,
        violations=(),
        reason="OK",
    )

    assert result.valid is True
    assert result.protected is True
    assert result.violations == ()
    assert result.reason == "OK"
