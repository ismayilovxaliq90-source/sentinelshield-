from sentinelshield.ignore_file_discovery import discover_ignore_files


def test_gitignore(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".gitignore").write_text("*.pyc\n")

    result = discover_ignore_files(root)

    assert result.found is True
    assert result.types == ("git",)


def test_dockerignore(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".dockerignore").write_text(".git\n")

    result = discover_ignore_files(root)

    assert result.found is True
    assert result.types == ("docker",)


def test_nested_ignore_file(tmp_path):
    root = tmp_path / "project"
    nested = root / "service"
    nested.mkdir(parents=True)
    (nested / ".npmignore").write_text("test/\n")

    result = discover_ignore_files(root)

    assert result.found is True
    assert result.types == ("npm",)


def test_git_info_exclude(tmp_path):
    root = tmp_path / "project"
    info = root / ".git" / "info"
    info.mkdir(parents=True)
    (info / "exclude").write_text("secret.txt\n")

    result = discover_ignore_files(root)

    assert result.found is True
    assert result.types == ("git-info",)


def test_multiple_types(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".gitignore").write_text("x\n")
    (root / ".dockerignore").write_text("y\n")
    (root / ".prettierignore").write_text("z\n")

    result = discover_ignore_files(root)

    assert result.found is True
    assert result.types == ("docker", "git", "prettier")


def test_ignored_directory_not_scanned(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    ignored = root / "node_modules"
    ignored.mkdir()
    (ignored / ".gitignore").write_text("must-not-be-found\n")

    result = discover_ignore_files(root)

    assert result.found is False


def test_no_ignore_files(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("test\n")

    result = discover_ignore_files(root)

    assert result.found is False
    assert result.reason == "IGNORE_FILES_NOT_FOUND"


def test_none():
    result = discover_ignore_files(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = discover_ignore_files("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = discover_ignore_files(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_ignore_files("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = discover_ignore_files(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file"
    file.write_text("x")

    result = discover_ignore_files(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_no_filesystem_modification(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".gitignore").write_text("*.log\n")

    before = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))

    discover_ignore_files(root)

    after = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))

    assert before == after
