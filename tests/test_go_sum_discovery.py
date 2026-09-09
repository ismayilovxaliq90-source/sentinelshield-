from pathlib import Path

from sentinelshield.go_sum_discovery import (
    GoSumDiscovery,
    GoSumDiscoveryResult,
    discover_go_sum,
)


def test_go_sum_is_discovered(tmp_path):
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(
        "example.com/dependency v1.2.3 h1:abcdef\n",
        encoding="utf-8",
    )

    result = discover_go_sum(tmp_path)

    assert isinstance(result, GoSumDiscoveryResult)
    assert result.found is True
    assert result.path == go_sum
    assert result.reason == "GO_SUM_FOUND"


def test_go_sum_is_not_found(tmp_path):
    result = discover_go_sum(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "GO_SUM_NOT_FOUND"


def test_nested_go_sum_is_not_selected(tmp_path):
    nested = tmp_path / "backend"
    nested.mkdir()

    go_sum = nested / "go.sum"
    go_sum.write_text(
        "example.com/dependency v1.2.3 h1:abcdef\n",
        encoding="utf-8",
    )

    result = discover_go_sum(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "GO_SUM_NOT_FOUND"


def test_go_sum_directory_is_rejected(tmp_path):
    (tmp_path / "go.sum").mkdir()

    result = discover_go_sum(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "GO_SUM_NOT_FILE"


def test_missing_project_root_is_rejected(tmp_path):
    missing = tmp_path / "does-not-exist"

    result = discover_go_sum(missing)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_NOT_FOUND"


def test_file_as_project_root_is_rejected(tmp_path):
    project_file = tmp_path / "project.txt"
    project_file.write_text("project", encoding="utf-8")

    result = discover_go_sum(project_file)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_NOT_DIRECTORY"


def test_none_project_root_is_rejected():
    result = discover_go_sum(None)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_IS_NONE"


def test_empty_project_root_is_rejected():
    result = discover_go_sum("")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_IS_EMPTY"


def test_whitespace_project_root_is_rejected():
    result = discover_go_sum("   ")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_IS_EMPTY"


def test_unsupported_project_root_type_is_rejected():
    result = discover_go_sum(123)

    assert result.found is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PROJECT_ROOT_TYPE"


def test_string_project_root_is_supported(tmp_path):
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(
        "example.com/dependency v1.2.3 h1:abcdef\n",
        encoding="utf-8",
    )

    result = discover_go_sum(str(tmp_path))

    assert result.found is True
    assert result.path == go_sum
    assert result.reason == "GO_SUM_FOUND"


def test_path_object_is_supported(tmp_path):
    go_sum = tmp_path / "go.sum"
    go_sum.write_text(
        "example.com/dependency v1.2.3 h1:abcdef\n",
        encoding="utf-8",
    )

    result = GoSumDiscovery().discover(Path(tmp_path))

    assert result.found is True
    assert result.path == go_sum
    assert result.reason == "GO_SUM_FOUND"


def test_discovery_does_not_create_files(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = discover_go_sum(tmp_path)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.found is False
    assert before == after


def test_existing_go_sum_content_is_not_modified(tmp_path):
    go_sum = tmp_path / "go.sum"
    content = (
        "example.com/dependency v1.2.3 h1:abcdef\n"
        "example.com/other v2.0.0/go.mod h1:123456\n"
    )
    go_sum.write_text(content, encoding="utf-8")

    result = discover_go_sum(tmp_path)

    assert result.found is True
    assert result.path == go_sum
    assert go_sum.read_text(encoding="utf-8") == content
