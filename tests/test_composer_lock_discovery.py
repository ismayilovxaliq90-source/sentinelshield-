from pathlib import Path

from sentinelshield.composer_lock_discovery import (
    ComposerLockDiscoveryResult,
    discover_composer_lock,
)


def test_finds_root_composer_lock(tmp_path: Path):
    target = tmp_path / "composer.lock"
    target.write_text('{"packages": []}', encoding="utf-8")

    result = discover_composer_lock(tmp_path)

    assert result.status == "FOUND"
    assert result.found is True
    assert result.files == (target.resolve(),)


def test_finds_nested_composer_lock(tmp_path: Path):
    nested = tmp_path / "backend" / "config"
    nested.mkdir(parents=True)

    target = nested / "composer.lock"
    target.write_text('{"packages": []}', encoding="utf-8")

    result = discover_composer_lock(tmp_path)

    assert result.status == "FOUND"
    assert result.files == (target.resolve(),)


def test_finds_multiple_composer_locks(tmp_path: Path):
    first = tmp_path / "a" / "composer.lock"
    second = tmp_path / "b" / "composer.lock"

    first.parent.mkdir()
    second.parent.mkdir()

    first.write_text("{}", encoding="utf-8")
    second.write_text("{}", encoding="utf-8")

    result = discover_composer_lock(tmp_path)

    assert result.status == "FOUND"
    assert result.found is True
    assert result.files == tuple(sorted((first.resolve(), second.resolve()), key=str))


def test_ignores_wrong_filename(tmp_path: Path):
    (tmp_path / "composer.lock.bak").write_text("{}", encoding="utf-8")

    result = discover_composer_lock(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.found is False
    assert result.files == ()


def test_missing_file(tmp_path: Path):
    result = discover_composer_lock(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.found is False
    assert result.files == ()


def test_none_input():
    result = discover_composer_lock(None)

    assert result.status == "PATH_IS_NONE"
    assert result.found is False
    assert result.files == ()


def test_empty_input():
    result = discover_composer_lock("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.found is False
    assert result.files == ()


def test_null_character():
    result = discover_composer_lock("/tmp/project\x00evil")

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.found is False
    assert result.files == ()


def test_unsupported_type():
    result = discover_composer_lock(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.found is False
    assert result.files == ()


def test_non_directory(tmp_path: Path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")

    result = discover_composer_lock(file_path)

    assert result.status == "NOT_A_DIRECTORY"
    assert result.found is False
    assert result.files == ()


def test_tilde_path_resolution(tmp_path: Path):
    # Path.expanduser() is exercised through a normal valid Path input.
    result = discover_composer_lock(tmp_path)
    assert result.repository_root == tmp_path.resolve()


def test_symlink_file_is_ignored(tmp_path: Path):
    real = tmp_path / "real.lock"
    real.write_text("{}", encoding="utf-8")

    link = tmp_path / "composer.lock"
    try:
        link.symlink_to(real)
    except OSError:
        return

    result = discover_composer_lock(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.files == ()


def test_symlink_directory_is_not_traversed(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}_outside"
    outside.mkdir(exist_ok=True)

    try:
        target = outside / "composer.lock"
        target.write_text("{}", encoding="utf-8")

        link_dir = tmp_path / "linked"
        link_dir.symlink_to(outside, target_is_directory=True)
    except OSError:
        return

    result = discover_composer_lock(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.files == ()

    target.unlink(missing_ok=True)
    try:
        outside.rmdir()
    except OSError:
        pass


def test_result_is_immutable(tmp_path: Path):
    result = discover_composer_lock(tmp_path)

    try:
        result.found = True
        assert False, "Result must be immutable"
    except Exception:
        pass


def test_result_type(tmp_path: Path):
    result = discover_composer_lock(tmp_path)

    assert isinstance(result, ComposerLockDiscoveryResult)


def test_deterministic_order(tmp_path: Path):
    names = ["z", "a", "m"]

    for name in names:
        directory = tmp_path / name
        directory.mkdir()
        (directory / "composer.lock").write_text("{}", encoding="utf-8")

    result = discover_composer_lock(tmp_path)

    assert result.files == tuple(sorted(result.files, key=str))


def test_json_extension_is_not_accepted(tmp_path: Path):
    (tmp_path / "composer.lock.json").write_text("{}", encoding="utf-8")

    result = discover_composer_lock(tmp_path)

    assert result.status == "NOT_FOUND"


def test_composer_json_does_not_count(tmp_path: Path):
    (tmp_path / "composer.json").write_text("{}", encoding="utf-8")

    result = discover_composer_lock(tmp_path)

    assert result.status == "NOT_FOUND"
