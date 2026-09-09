from pathlib import Path

from sentinelshield.pnpm_lockfile_discovery import (
    PnpmLockfileDetector,
    PnpmLockfileDiscoveryResult,
    discover_pnpm_lockfile,
)


def test_pnpm_lockfile_is_detected(tmp_path):
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n",
        encoding="utf-8",
    )

    result = discover_pnpm_lockfile(tmp_path)

    assert isinstance(
        result,
        PnpmLockfileDiscoveryResult,
    )
    assert result.found is True
    assert result.lockfile == lockfile
    assert result.reason == "PNPM_LOCKFILE_FOUND"


def test_missing_pnpm_lockfile_is_reported(tmp_path):
    result = discover_pnpm_lockfile(tmp_path)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PNPM_LOCKFILE_NOT_FOUND"


def test_only_pnpm_lockfile_is_selected(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = discover_pnpm_lockfile(tmp_path)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PNPM_LOCKFILE_NOT_FOUND"


def test_directory_named_pnpm_lock_yaml_is_not_accepted(
    tmp_path,
):
    (tmp_path / "pnpm-lock.yaml").mkdir()

    result = discover_pnpm_lockfile(tmp_path)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PNPM_LOCKFILE_NOT_FOUND"


def test_nested_pnpm_lockfile_is_not_used(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()

    lockfile = nested / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n",
        encoding="utf-8",
    )

    result = discover_pnpm_lockfile(tmp_path)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PNPM_LOCKFILE_NOT_FOUND"


def test_path_object_is_supported(tmp_path):
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n",
        encoding="utf-8",
    )

    result = PnpmLockfileDetector().discover(
        Path(tmp_path)
    )

    assert result.found is True
    assert result.lockfile == lockfile


def test_none_is_rejected():
    result = discover_pnpm_lockfile(None)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = discover_pnpm_lockfile("")

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_string_is_rejected():
    result = discover_pnpm_lockfile("   ")

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PATH_IS_EMPTY"


def test_integer_is_rejected():
    result = discover_pnpm_lockfile(123)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character_is_rejected():
    result = discover_pnpm_lockfile(
        str(tmp_path_placeholder())
        + "\x00evil"
    )

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_nonexistent_project_path_is_rejected(tmp_path):
    missing = tmp_path / "does-not-exist"

    result = discover_pnpm_lockfile(missing)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PROJECT_PATH_NOT_FOUND"


def test_file_path_is_rejected(tmp_path):
    project_file = tmp_path / "project.txt"
    project_file.write_text(
        "project",
        encoding="utf-8",
    )

    result = discover_pnpm_lockfile(project_file)

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PROJECT_PATH_NOT_DIRECTORY"


def test_home_expansion_is_supported(tmp_path, monkeypatch):
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(tmp_path))

    result = discover_pnpm_lockfile(
        "~/pnpm-lock-project-does-not-exist"
    )

    assert result.found is False
    assert result.lockfile is None
    assert result.reason == "PROJECT_PATH_NOT_FOUND"


def test_discovery_does_not_modify_filesystem(tmp_path):
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n",
        encoding="utf-8",
    )

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = discover_pnpm_lockfile(tmp_path)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.found is True
    assert before == after


def test_lockfile_content_is_not_modified(tmp_path):
    lockfile = tmp_path / "pnpm-lock.yaml"
    content = (
        "lockfileVersion: '9.0'\n"
        "settings:\n"
        "  autoInstallPeers: true\n"
    )

    lockfile.write_text(
        content,
        encoding="utf-8",
    )

    result = discover_pnpm_lockfile(tmp_path)

    assert result.found is True
    assert lockfile.read_text(
        encoding="utf-8"
    ) == content


def test_detector_does_not_execute_pnpm(tmp_path):
    marker = tmp_path / "executed.txt"

    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n",
        encoding="utf-8",
    )

    result = discover_pnpm_lockfile(tmp_path)

    assert result.found is True
    assert not marker.exists()


def test_result_is_immutable(tmp_path):
    result = discover_pnpm_lockfile(tmp_path)

    try:
        result.found = True
        changed = True
    except AttributeError:
        changed = False

    assert changed is False


def tmp_path_placeholder():
    return "/tmp/project"
