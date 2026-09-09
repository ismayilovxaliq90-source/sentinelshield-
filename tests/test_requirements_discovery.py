from pathlib import Path

from sentinelshield.requirements_discovery import (
    discover_requirements_txt,
)


def test_root_requirements_found(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.32.0\n")

    result = discover_requirements_txt(root)

    assert result.found is True
    assert result.files == (Path("requirements.txt"),)
    assert result.count == 1
    assert result.reason == "REQUIREMENTS_TXT_DISCOVERED"


def test_nested_requirements_found(tmp_path):
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("flask\n")

    result = discover_requirements_txt(root)

    assert result.found is True
    assert result.files == (
        Path("services/api/requirements.txt"),
    )


def test_multiple_requirements_files(tmp_path):
    root = tmp_path / "project"
    (root / "api").mkdir(parents=True)
    (root / "web").mkdir()

    (root / "requirements.txt").write_text("")
    (root / "api" / "requirements.txt").write_text("")
    (root / "web" / "requirements.txt").write_text("")

    result = discover_requirements_txt(root)

    assert result.count == 3
    assert result.files == (
        Path("api/requirements.txt"),
        Path("requirements.txt"),
        Path("web/requirements.txt"),
    )


def test_result_paths_are_relative(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("")

    result = discover_requirements_txt(root)

    assert all(not path.is_absolute() for path in result.files)


def test_only_exact_filename_matches(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    (root / "requirements-dev.txt").write_text("")
    (root / "requirements-prod.txt").write_text("")
    (root / "requirements.txt.bak").write_text("")

    result = discover_requirements_txt(root)

    assert result.found is False
    assert result.files == ()
    assert result.reason == "REQUIREMENTS_TXT_NOT_FOUND"


def test_case_sensitive_filename(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    (root / "Requirements.txt").write_text("")

    result = discover_requirements_txt(root)

    assert result.found is False


def test_ignored_venv_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / ".venv"
    ignored.mkdir(parents=True)
    (ignored / "requirements.txt").write_text("")

    result = discover_requirements_txt(root)

    assert result.found is False


def test_ignored_node_modules_not_scanned(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules" / "pkg"
    ignored.mkdir(parents=True)
    (ignored / "requirements.txt").write_text("")

    result = discover_requirements_txt(root)

    assert result.found is False


def test_symlink_file_is_ignored(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "requirements.txt"
    root.mkdir()
    target.write_text("")
    (root / "requirements.txt").symlink_to(target)

    result = discover_requirements_txt(root)

    assert result.found is False


def test_symlink_directory_is_not_followed(tmp_path):
    root = tmp_path / "project"
    target = tmp_path / "external"
    root.mkdir()
    target.mkdir()
    (target / "requirements.txt").write_text("")

    (root / "linked").symlink_to(target, target_is_directory=True)

    result = discover_requirements_txt(root)

    assert result.found is False


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    (root / "z").mkdir(parents=True)
    (root / "a").mkdir()

    (root / "z" / "requirements.txt").write_text("")
    (root / "requirements.txt").write_text("")
    (root / "a" / "requirements.txt").write_text("")

    result = discover_requirements_txt(root)

    assert result.files == (
        Path("a/requirements.txt"),
        Path("requirements.txt"),
        Path("z/requirements.txt"),
    )


def test_no_requirements(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("x")

    result = discover_requirements_txt(root)

    assert result.found is False
    assert result.count == 0
    assert result.files == ()
    assert result.reason == "REQUIREMENTS_TXT_NOT_FOUND"


def test_none():
    result = discover_requirements_txt(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_requirements_txt("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_requirements_txt(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_requirements_txt("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_requirements_txt(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "requirements.txt"
    file.write_text("")

    result = discover_requirements_txt(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"
