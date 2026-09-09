from pathlib import Path

from sentinelshield.repository_root_detection import (
    RepositoryRootDetectionResult,
    RepositoryRootDetector,
    detect_repository_root,
)


def test_git_repository_root_is_detected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()

    result = detect_repository_root(root)

    assert isinstance(
        result,
        RepositoryRootDetectionResult,
    )
    assert result.found is True
    assert result.root == root
    assert ".git" in result.markers
    assert result.reason == "REPOSITORY_ROOT_FOUND"


def test_nested_directory_finds_git_root(tmp_path):
    root = tmp_path / "project"
    nested = root / "src" / "package"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()

    result = detect_repository_root(nested)

    assert result.found is True
    assert result.root == root
    assert ".git" in result.markers


def test_nearest_root_is_selected(tmp_path):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    nested = inner / "src"

    nested.mkdir(parents=True)
    (outer / ".git").mkdir()
    (inner / ".git").mkdir()

    result = detect_repository_root(nested)

    assert result.found is True
    assert result.root == inner


def test_pyproject_is_project_marker(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "[project]\nname='demo'\n",
        encoding="utf-8",
    )

    result = detect_repository_root(root)

    assert result.found is True
    assert result.root == root
    assert "pyproject.toml" in result.markers


def test_package_json_is_project_marker(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_repository_root(root)

    assert result.found is True
    assert result.root == root
    assert "package.json" in result.markers


def test_go_mod_is_project_marker(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "go.mod").write_text(
        "module example.com/demo\n",
        encoding="utf-8",
    )

    result = detect_repository_root(root)

    assert result.found is True
    assert result.root == root
    assert "go.mod" in result.markers


def test_cargo_toml_is_project_marker(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Cargo.toml").write_text(
        "[package]\nname='demo'\n",
        encoding="utf-8",
    )

    result = detect_repository_root(root)

    assert result.found is True
    assert result.root == root
    assert "Cargo.toml" in result.markers


def test_sln_file_is_project_marker(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "demo.sln").write_text(
        "",
        encoding="utf-8",
    )

    result = detect_repository_root(root)

    assert result.found is True
    assert result.root == root
    assert "*.sln" in result.markers


def test_file_input_starts_from_parent(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()

    source_file = root / "main.py"
    source_file.write_text(
        "print('test')\n",
        encoding="utf-8",
    )

    result = detect_repository_root(source_file)

    assert result.found is True
    assert result.root == root


def test_no_root_is_reported(tmp_path):
    isolated = tmp_path / "isolated"
    isolated.mkdir()

    result = detect_repository_root(isolated)

    assert result.found is False
    assert result.root is None
    assert result.markers == ()
    assert result.reason == "REPOSITORY_ROOT_NOT_FOUND"


def test_none_is_rejected():
    result = detect_repository_root(None)

    assert result.found is False
    assert result.root is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = detect_repository_root("")

    assert result.found is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_only_is_rejected():
    result = detect_repository_root("   ")

    assert result.found is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = detect_repository_root(
        "/tmp/project\x00evil"
    )

    assert result.found is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = detect_repository_root(123)

    assert result.found is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_path_object_is_supported(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()

    result = RepositoryRootDetector().detect(root)

    assert result.found is True
    assert result.root == root


def test_multiple_markers_are_returned(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "pyproject.toml").write_text(
        "[project]\nname='demo'\n",
        encoding="utf-8",
    )

    result = detect_repository_root(root)

    assert result.found is True
    assert ".git" in result.markers
    assert "pyproject.toml" in result.markers


def test_detection_does_not_modify_filesystem(tmp_path):
    root = tmp_path / "project"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = detect_repository_root(nested)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.found is True
    assert before == after


def test_detector_does_not_execute_project_code(
    tmp_path,
):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".git").mkdir()

    marker = root / "executed.txt"

    (root / "setup.py").write_text(
        f"open({str(marker)!r}, 'w').write('executed')\n",
        encoding="utf-8",
    )

    result = detect_repository_root(root)

    assert result.found is True
    assert not marker.exists()
