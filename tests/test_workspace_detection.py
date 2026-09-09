from pathlib import Path

from sentinelshield.workspace_detection import (
    WorkspaceDetectionResult,
    WorkspaceDetector,
    detect_workspace,
)


def test_pnpm_workspace_marker_is_detected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "pnpm-workspace.yaml").write_text(
        "packages:\n  - packages/*\n",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert isinstance(
        result,
        WorkspaceDetectionResult,
    )
    assert result.is_workspace is True
    assert result.workspace_path == root
    assert "pnpm-workspace.yaml" in result.markers
    assert result.reason == "WORKSPACE_MARKER_FOUND"


def test_lerna_workspace_marker_is_detected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "lerna.json").write_text(
        '{"version":"1.0.0"}',
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is True
    assert "lerna.json" in result.markers


def test_nx_workspace_marker_is_detected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "nx.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is True
    assert "nx.json" in result.markers


def test_rush_workspace_marker_is_detected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "rush.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is True
    assert "rush.json" in result.markers


def test_two_package_projects_are_detected(tmp_path):
    root = tmp_path / "repo"
    app = root / "packages" / "app"
    web = root / "packages" / "web"

    app.mkdir(parents=True)
    web.mkdir(parents=True)

    (app / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (web / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is True
    assert app in result.package_projects
    assert web in result.package_projects
    assert result.reason == "MULTIPLE_PACKAGE_PROJECTS_FOUND"


def test_single_project_is_not_workspace(tmp_path):
    root = tmp_path / "repo"
    app = root / "app"

    app.mkdir(parents=True)

    (app / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is False
    assert result.package_projects == (app,)
    assert result.reason == "WORKSPACE_NOT_DETECTED"


def test_empty_directory_is_not_workspace(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    result = detect_workspace(root)

    assert result.is_workspace is False
    assert result.markers == ()
    assert result.package_projects == ()
    assert result.reason == "WORKSPACE_NOT_DETECTED"


def test_none_is_rejected():
    result = detect_workspace(None)

    assert result.is_workspace is False
    assert result.workspace_path is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = detect_workspace("")

    assert result.is_workspace is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_is_rejected():
    result = detect_workspace("   ")

    assert result.is_workspace is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = detect_workspace(
        "/tmp/project\x00evil"
    )

    assert result.is_workspace is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = detect_workspace(123)

    assert result.is_workspace is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_path_object_is_supported(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "nx.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = WorkspaceDetector().detect(
        Path(root)
    )

    assert result.is_workspace is True
    assert result.workspace_path == root


def test_file_input_uses_parent(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "nx.json").write_text(
        "{}",
        encoding="utf-8",
    )

    readme = root / "README.md"
    readme.write_text(
        "# demo",
        encoding="utf-8",
    )

    result = detect_workspace(readme)

    assert result.workspace_path == root
    assert result.is_workspace is True


def test_missing_directory_is_reported(tmp_path):
    missing = tmp_path / "missing"

    result = detect_workspace(missing)

    assert result.is_workspace is False
    assert result.workspace_path == missing
    assert result.reason == "DIRECTORY_NOT_FOUND"


def test_node_modules_is_ignored(tmp_path):
    root = tmp_path / "repo"
    dependency = (
        root / "node_modules" / "dependency"
    )

    dependency.mkdir(parents=True)

    (dependency / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is False
    assert dependency not in result.package_projects


def test_git_directory_is_ignored(tmp_path):
    root = tmp_path / "repo"
    git_dir = root / ".git" / "objects"

    git_dir.mkdir(parents=True)

    (git_dir / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is False


def test_detection_does_not_modify_filesystem(tmp_path):
    root = tmp_path / "repo"
    packages = root / "packages"
    packages.mkdir(parents=True)

    (packages / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = detect_workspace(root)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.is_workspace is False
    assert before == after


def test_detector_does_not_execute_project_code(
    tmp_path,
):
    root = tmp_path / "repo"
    root.mkdir()

    marker = root / "executed.txt"

    (root / "setup.py").write_text(
        f"open({str(marker)!r}, 'w').write('executed')\n",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert not marker.exists()
    assert result.is_workspace is False


def test_multiple_markers_are_all_returned(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "nx.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (root / "lerna.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    assert result.is_workspace is True
    assert result.markers == (
        "lerna.json",
        "nx.json",
    )


def test_result_is_immutable(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "nx.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_workspace(root)

    try:
        result.is_workspace = False
        changed = True
    except Exception:
        changed = False

    assert changed is False
    assert result.is_workspace is True
