from sentinelshield.documentation_discovery import discover_documentation


def test_readme(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# Project\n")

    result = discover_documentation(root)

    assert result.found is True
    assert result.categories == ("readme",)


def test_docs_directory(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "docs").mkdir()

    result = discover_documentation(root)

    assert result.found is True
    assert result.categories == ("docs",)


def test_nested_readme(tmp_path):
    root = tmp_path / "project"
    nested = root / "service"
    nested.mkdir(parents=True)
    (nested / "README.rst").write_text("Service\n")

    result = discover_documentation(root)

    assert result.found is True
    assert result.categories == ("readme",)


def test_changelog(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "CHANGELOG.md").write_text("# Changes\n")

    result = discover_documentation(root)

    assert result.found is True
    assert result.categories == ("changelog",)


def test_contributing(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "CONTRIBUTING.md").write_text("# Contributing\n")

    result = discover_documentation(root)

    assert result.found is True
    assert result.categories == ("contributing",)


def test_license(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "LICENSE").write_text("License\n")

    result = discover_documentation(root)

    assert result.found is True
    assert result.categories == ("license",)


def test_multiple_categories(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("README\n")
    (root / "CHANGELOG.md").write_text("Changes\n")
    (root / "docs").mkdir()

    result = discover_documentation(root)

    assert result.found is True
    assert result.categories == ("changelog", "docs", "readme")


def test_ignored_directory(tmp_path):
    root = tmp_path / "project"
    ignored = root / "node_modules"
    ignored.mkdir(parents=True)
    (ignored / "README.md").write_text("ignored\n")

    result = discover_documentation(root)

    assert result.found is False


def test_no_documentation(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("print('x')\n")

    result = discover_documentation(root)

    assert result.found is False
    assert result.reason == "DOCUMENTATION_NOT_FOUND"


def test_none():
    assert discover_documentation(None).reason == "PATH_IS_NONE"


def test_empty():
    assert discover_documentation("   ").reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    assert discover_documentation(123).reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = discover_documentation("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_file_path(tmp_path):
    file = tmp_path / "README.md"
    file.write_text("x")

    result = discover_documentation(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_missing_path(tmp_path):
    result = discover_documentation(tmp_path / "missing")

    assert result.reason == "PATH_DOES_NOT_EXIST"
