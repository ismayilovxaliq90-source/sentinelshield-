from pathlib import Path

from sentinelshield.source_tree_discovery import (
    SourceTreeDiscoveryResult,
    SourceTreeDetector,
    discover_source_tree,
)


def test_src_directory_is_detected(tmp_path):
    root = tmp_path / "project"
    src = root / "src"
    src.mkdir(parents=True)

    result = discover_source_tree(root)

    assert isinstance(
        result,
        SourceTreeDiscoveryResult,
    )
    assert result.valid is True
    assert result.project_root == root
    assert result.source_roots == (src,)
    assert result.reason == "SOURCE_TREE_DISCOVERY_SUCCESS"


def test_app_directory_is_detected(tmp_path):
    root = tmp_path / "project"
    app = root / "app"
    app.mkdir(parents=True)

    result = discover_source_tree(root)

    assert result.source_roots == (app,)


def test_nested_source_directory_is_detected(tmp_path):
    root = tmp_path / "project"
    source = root / "packages" / "api" / "src"
    source.mkdir(parents=True)

    result = discover_source_tree(root)

    assert source in result.source_roots


def test_build_directory_is_ignored(tmp_path):
    root = tmp_path / "project"
    build = root / "build" / "src"
    build.mkdir(parents=True)

    result = discover_source_tree(root)

    assert build not in result.source_roots


def test_node_modules_is_ignored(tmp_path):
    root = tmp_path / "project"
    node = root / "node_modules" / "pkg" / "src"
    node.mkdir(parents=True)

    result = discover_source_tree(root)

    assert node not in result.source_roots


def test_git_is_ignored(tmp_path):
    root = tmp_path / "project"
    git = root / ".git" / "src"
    git.mkdir(parents=True)

    result = discover_source_tree(root)

    assert git not in result.source_roots


def test_no_source_directory_is_valid(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_source_tree(root)

    assert result.valid is True
    assert result.source_roots == ()
    assert result.reason == "SOURCE_TREE_DISCOVERY_SUCCESS"


def test_none_is_rejected():
    result = discover_source_tree(None)

    assert result.valid is False
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = discover_source_tree("")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_is_rejected():
    result = discover_source_tree("   ")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = discover_source_tree(
        "/tmp/project\x00evil"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = discover_source_tree(123)

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_path_object_is_supported(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = SourceTreeDetector().discover(
        Path(root)
    )

    assert result.valid is True
    assert result.project_root == root


def test_file_input_uses_parent(tmp_path):
    root = tmp_path / "project"
    src = root / "src"
    src.mkdir(parents=True)

    readme = root / "README.md"
    readme.write_text(
        "# project",
        encoding="utf-8",
    )

    result = discover_source_tree(readme)

    assert result.project_root == root
    assert src in result.source_roots


def test_missing_directory_is_rejected(tmp_path):
    root = tmp_path / "missing"

    result = discover_source_tree(root)

    assert result.valid is False
    assert result.reason == "DIRECTORY_NOT_FOUND"


def test_filesystem_is_not_modified(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)

    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    discover_source_tree(root)

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert before == after


def test_project_code_is_not_executed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    marker = tmp_path / "executed.txt"

    (root / "setup.py").write_text(
        f"open({str(marker)!r}, 'w').write('executed')",
        encoding="utf-8",
    )

    result = discover_source_tree(root)

    assert result.valid is True
    assert not marker.exists()


def test_source_roots_are_tuple(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)

    result = discover_source_tree(root)

    assert isinstance(
        result.source_roots,
        tuple,
    )


def test_result_is_immutable(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_source_tree(root)

    try:
        result.valid = False
        changed = True
    except Exception:
        changed = False

    assert changed is False
    assert result.valid is True
