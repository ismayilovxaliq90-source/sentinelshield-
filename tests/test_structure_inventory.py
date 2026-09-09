from pathlib import Path

from sentinelshield.structure_inventory import (
    collect_structure_inventory,
)


def test_basic_inventory(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("x")
    (root / "main.py").write_text("x")

    result = collect_structure_inventory(root)

    assert result.found is True
    assert result.file_count == 2
    assert result.directory_count == 0


def test_nested_structure(tmp_path):
    root = tmp_path / "project"
    src = root / "src" / "app"
    src.mkdir(parents=True)
    (src / "main.py").write_text("x")

    result = collect_structure_inventory(root)

    assert result.file_count == 1
    assert result.directory_count == 2
    assert result.max_depth == 2


def test_paths_are_relative(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("x")

    result = collect_structure_inventory(root)

    assert result.files == (Path("main.py"),)


def test_deterministic_order(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "z.txt").write_text("x")
    (root / "a.txt").write_text("x")
    (root / "m.txt").write_text("x")

    result = collect_structure_inventory(root)

    assert result.files == (
        Path("a.txt"),
        Path("m.txt"),
        Path("z.txt"),
    )


def test_ignored_directories(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    ignored = root / "node_modules"
    ignored.mkdir()
    (ignored / "package.js").write_text("x")

    normal = root / "src"
    normal.mkdir()
    (normal / "main.py").write_text("x")

    result = collect_structure_inventory(root)

    assert result.file_count == 1
    assert result.directory_count == 1
    assert Path("src") in result.directories
    assert Path("node_modules") not in result.directories


def test_multiple_levels(tmp_path):
    root = tmp_path / "project"
    deep = root / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "file.txt").write_text("x")

    result = collect_structure_inventory(root)

    assert result.file_count == 1
    assert result.directory_count == 3
    assert result.max_depth == 3


def test_symlink_is_not_followed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    target = root / "target"
    target.mkdir()
    (target / "file.txt").write_text("x")

    link = root / "link"
    link.symlink_to(target, target_is_directory=True)

    result = collect_structure_inventory(root)

    assert Path("link") not in result.directories
    assert Path("link/file.txt") not in result.files


def test_empty_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = collect_structure_inventory(root)

    assert result.found is True
    assert result.file_count == 0
    assert result.directory_count == 0
    assert result.max_depth == 0


def test_none():
    result = collect_structure_inventory(None)
    assert result.reason == "PATH_IS_NONE"


def test_empty():
    result = collect_structure_inventory("   ")
    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_type():
    result = collect_structure_inventory(123)
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = collect_structure_inventory("/tmp/a\x00b")
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_path(tmp_path):
    result = collect_structure_inventory(tmp_path / "missing")
    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_path(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = collect_structure_inventory(file)

    assert result.reason == "PATH_IS_NOT_DIRECTORY"
