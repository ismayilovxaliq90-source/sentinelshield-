from pathlib import Path

from sentinelshield.symlink_policy import (
    SymlinkPolicyResult,
    validate_symlink_policy,
)


def test_normal_directory_is_accepted(tmp_path):
    result = validate_symlink_policy(tmp_path)

    assert isinstance(result, SymlinkPolicyResult)
    assert result.valid is True
    assert result.path == tmp_path
    assert result.is_symlink is False
    assert result.reason == "SYMLINK_POLICY_ACCEPTED"


def test_directory_symlink_is_rejected(tmp_path):
    target = tmp_path / "real-project"
    link = tmp_path / "project-link"

    target.mkdir()
    link.symlink_to(target, target_is_directory=True)

    result = validate_symlink_policy(link)

    assert result.valid is False
    assert result.path == link
    assert result.is_symlink is True
    assert result.reason == "SYMLINK_NOT_ALLOWED"


def test_file_symlink_is_rejected(tmp_path):
    target = tmp_path / "real-file"
    link = tmp_path / "file-link"

    target.write_text("test", encoding="utf-8")
    link.symlink_to(target)

    result = validate_symlink_policy(link)

    assert result.valid is False
    assert result.is_symlink is True
    assert result.reason == "SYMLINK_NOT_ALLOWED"


def test_broken_symlink_is_rejected(tmp_path):
    link = tmp_path / "broken-link"

    link.symlink_to(
        tmp_path / "does-not-exist",
        target_is_directory=True,
    )

    result = validate_symlink_policy(link)

    assert result.valid is False
    assert result.path == link
    assert result.is_symlink is True
    assert result.reason == "SYMLINK_NOT_ALLOWED"


def test_regular_file_is_rejected(tmp_path):
    file_path = tmp_path / "project.txt"
    file_path.write_text("test", encoding="utf-8")

    result = validate_symlink_policy(file_path)

    assert result.valid is False
    assert result.is_symlink is False
    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_missing_path_is_rejected(tmp_path):
    missing = tmp_path / "missing"

    result = validate_symlink_policy(missing)

    assert result.valid is False
    assert result.reason == "PATH_NOT_FOUND"


def test_none_is_rejected():
    result = validate_symlink_policy(None)

    assert result.valid is False
    assert result.path is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_path_is_rejected():
    result = validate_symlink_policy("")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only_is_rejected():
    result = validate_symlink_policy("   ")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = validate_symlink_policy(
        "/tmp/project\x00evil"
    )

    assert result.valid is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_unsupported_type_is_rejected():
    result = validate_symlink_policy(123)

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_symlink_target_is_not_modified(tmp_path):
    target = tmp_path / "real-project"
    link = tmp_path / "project-link"

    target.mkdir()
    (target / "marker.txt").write_text(
        "unchanged",
        encoding="utf-8",
    )

    link.symlink_to(target, target_is_directory=True)

    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    result = validate_symlink_policy(link)

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert result.valid is False
    assert result.reason == "SYMLINK_NOT_ALLOWED"
    assert before == after
    assert (
        (target / "marker.txt").read_text(
            encoding="utf-8"
        )
        == "unchanged"
    )


def test_permission_error_is_handled(
    monkeypatch,
    tmp_path,
):
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self):
        if self == tmp_path:
            raise PermissionError("denied")
        return original_is_symlink(self)

    monkeypatch.setattr(
        Path,
        "is_symlink",
        fake_is_symlink,
    )

    result = validate_symlink_policy(tmp_path)

    assert result.valid is False
    assert result.reason == (
        "FILESYSTEM_PERMISSION_DENIED"
    )


def test_os_error_is_handled(
    monkeypatch,
    tmp_path,
):
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self):
        if self == tmp_path:
            raise OSError("filesystem failure")
        return original_is_symlink(self)

    monkeypatch.setattr(
        Path,
        "is_symlink",
        fake_is_symlink,
    )

    result = validate_symlink_policy(tmp_path)

    assert result.valid is False
    assert result.reason == "FILESYSTEM_OS_ERROR"
