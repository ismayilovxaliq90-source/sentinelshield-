from pathlib import Path

from sentinelshield.go_mod_discovery import (
    GoModDiscoveryResult,
    GoModDiscovery,
    discover_go_mod,
)


def test_go_mod_is_discovered(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module example.com/project\n\ngo 1.23\n",
        encoding="utf-8",
    )

    result = discover_go_mod(tmp_path)

    assert isinstance(result, GoModDiscoveryResult)
    assert result.found is True
    assert result.path == go_mod
    assert result.reason == "GO_MOD_FOUND"


def test_go_mod_is_not_found(tmp_path):
    result = discover_go_mod(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "GO_MOD_NOT_FOUND"


def test_nested_go_mod_is_not_selected(tmp_path):
    nested = tmp_path / "backend"
    nested.mkdir()

    go_mod = nested / "go.mod"
    go_mod.write_text(
        "module example.com/backend\n",
        encoding="utf-8",
    )

    result = discover_go_mod(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "GO_MOD_NOT_FOUND"


def test_go_mod_directory_is_rejected(tmp_path):
    (tmp_path / "go.mod").mkdir()

    result = discover_go_mod(tmp_path)

    assert result.found is False
    assert result.path is None
    assert result.reason == "GO_MOD_NOT_FILE"


def test_missing_project_root_is_rejected(tmp_path):
    missing = tmp_path / "does-not-exist"

    result = discover_go_mod(missing)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_NOT_FOUND"


def test_file_as_project_root_is_rejected(tmp_path):
    project_file = tmp_path / "project.txt"
    project_file.write_text("x", encoding="utf-8")

    result = discover_go_mod(project_file)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_NOT_DIRECTORY"


def test_none_project_root_is_rejected():
    result = discover_go_mod(None)

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_IS_NONE"


def test_empty_project_root_is_rejected():
    result = discover_go_mod("")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_IS_EMPTY"


def test_whitespace_project_root_is_rejected():
    result = discover_go_mod("   ")

    assert result.found is False
    assert result.path is None
    assert result.reason == "PROJECT_ROOT_IS_EMPTY"


def test_unsupported_project_root_type_is_rejected():
    result = discover_go_mod(123)

    assert result.found is False
    assert result.path is None
    assert result.reason == "UNSUPPORTED_PROJECT_ROOT_TYPE"


def test_string_project_root_is_supported(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module example.com/project\n",
        encoding="utf-8",
    )

    result = discover_go_mod(str(tmp_path))

    assert result.found is True
    assert result.path == go_mod
    assert result.reason == "GO_MOD_FOUND"


def test_path_object_is_supported(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module example.com/project\n",
        encoding="utf-8",
    )

    result = GoModDiscovery().discover(Path(tmp_path))

    assert result.found is True
    assert result.path == go_mod


def test_discovery_does_not_modify_filesystem(tmp_path):
    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = discover_go_mod(tmp_path)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.found is False
    assert before == after


def test_go_mod_content_is_not_modified(tmp_path):
    go_mod = tmp_path / "go.mod"
    content = "module example.com/project\n\ngo 1.23\n"
    go_mod.write_text(content, encoding="utf-8")

    result = discover_go_mod(tmp_path)

    assert result.found is True
    assert go_mod.read_text(encoding="utf-8") == content
