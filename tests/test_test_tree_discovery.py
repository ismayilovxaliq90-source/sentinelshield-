from pathlib import Path

from sentinelshield.test_tree_discovery import (
    TestTreeDiscoveryResult,
    TestTreeDetector,
    discover_test_tree,
)


def test_tests_directory_is_detected(tmp_path):
    root = tmp_path / "project"
    tests = root / "tests"
    tests.mkdir(parents=True)

    result = discover_test_tree(root)

    assert isinstance(result, TestTreeDiscoveryResult)
    assert result.valid is True
    assert result.project_root == root
    assert result.test_roots == (tests,)
    assert result.reason == "TEST_TREE_DISCOVERY_SUCCESS"


def test_test_directory_is_detected(tmp_path):
    root = tmp_path / "project"
    tests = root / "test"
    tests.mkdir(parents=True)

    result = discover_test_tree(root)

    assert tests in result.test_roots


def test_nested_tests_directory_is_detected(tmp_path):
    root = tmp_path / "project"
    tests = root / "packages" / "api" / "tests"
    tests.mkdir(parents=True)

    result = discover_test_tree(root)

    assert tests in result.test_roots


def test_node_modules_is_ignored(tmp_path):
    root = tmp_path / "project"
    tests = root / "node_modules" / "pkg" / "tests"
    tests.mkdir(parents=True)

    result = discover_test_tree(root)

    assert tests not in result.test_roots


def test_build_is_ignored(tmp_path):
    root = tmp_path / "project"
    tests = root / "build" / "tests"
    tests.mkdir(parents=True)

    result = discover_test_tree(root)

    assert tests not in result.test_roots


def test_no_tests_is_valid(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_test_tree(root)

    assert result.valid is True
    assert result.test_roots == ()


def test_none_is_rejected():
    result = discover_test_tree(None)

    assert result.valid is False
    assert result.reason == "PATH_IS_NONE"


def test_empty_is_rejected():
    result = discover_test_tree("")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = discover_test_tree("/tmp/project\x00evil")

    assert result.valid is False
    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_integer_is_rejected():
    result = discover_test_tree(123)

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_path_object_is_supported(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = TestTreeDetector().discover(Path(root))

    assert result.valid is True


def test_file_input_uses_parent(tmp_path):
    root = tmp_path / "project"
    tests = root / "tests"
    tests.mkdir(parents=True)

    readme = root / "README.md"
    readme.write_text("# project", encoding="utf-8")

    result = discover_test_tree(readme)

    assert result.project_root == root
    assert tests in result.test_roots


def test_filesystem_is_not_modified(tmp_path):
    root = tmp_path / "project"
    (root / "tests").mkdir(parents=True)

    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    discover_test_tree(root)

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert before == after
