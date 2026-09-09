from pathlib import Path

from sentinelshield.monorepo_detection import (
    MonorepoDetectionResult,
    MonorepoDetector,
    detect_monorepo,
)


def test_two_child_projects_are_monorepo(tmp_path):
    root = tmp_path / "repo"
    app = root / "packages" / "app"
    api = root / "packages" / "api"

    app.mkdir(parents=True)
    api.mkdir(parents=True)

    (app / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (api / "pyproject.toml").write_text(
        "[project]\nname='api'\n",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert isinstance(
        result,
        MonorepoDetectionResult,
    )
    assert result.is_monorepo is True
    assert result.repository_path == root
    assert app in result.project_roots
    assert api in result.project_roots
    assert result.reason == "MONOREPO_DETECTED"


def test_workspace_marker_detects_monorepo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "pnpm-workspace.yaml").write_text(
        "packages:\n  - packages/*\n",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is True
    assert "pnpm-workspace.yaml" in (
        result.workspace_markers
    )
    assert result.reason == "MONOREPO_DETECTED"


def test_lerna_marker_detects_monorepo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "lerna.json").write_text(
        '{"version": "1.0.0"}',
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is True
    assert "lerna.json" in result.workspace_markers


def test_nx_marker_detects_monorepo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "nx.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is True
    assert "nx.json" in result.workspace_markers


def test_single_project_is_not_monorepo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "pyproject.toml").write_text(
        "[project]\nname='demo'\n",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is False
    assert result.project_roots == (root,)
    assert result.reason == "MONOREPO_NOT_DETECTED"


def test_empty_repository_is_not_monorepo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    result = detect_monorepo(root)

    assert result.is_monorepo is False
    assert result.project_roots == ()
    assert result.reason == "MONOREPO_NOT_DETECTED"


def test_root_and_child_projects_are_detected(tmp_path):
    root = tmp_path / "repo"
    child = root / "service"

    child.mkdir(parents=True)

    (root / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (child / "pyproject.toml").write_text(
        "[project]\nname='service'\n",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is True
    assert root in result.project_roots
    assert child in result.project_roots


def test_node_modules_is_ignored(tmp_path):
    root = tmp_path / "repo"
    node_modules = root / "node_modules" / "dependency"

    node_modules.mkdir(parents=True)

    (node_modules / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is False
    assert node_modules not in result.project_roots


def test_git_directory_is_ignored(tmp_path):
    root = tmp_path / "repo"
    git_project = root / ".git" / "objects"

    git_project.mkdir(parents=True)

    (git_project / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is False


def test_none_is_rejected():
    result = detect_monorepo(None)

    assert result.is_monorepo is False
    assert result.repository_path is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = detect_monorepo("")

    assert result.is_monorepo is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_is_rejected():
    result = detect_monorepo("   ")

    assert result.is_monorepo is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = detect_monorepo(
        "/tmp/project\x00evil"
    )

    assert result.is_monorepo is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = detect_monorepo(123)

    assert result.is_monorepo is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_path_object_is_supported(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = MonorepoDetector().detect(
        Path(root)
    )

    assert result.repository_path == root


def test_file_input_uses_parent(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    (root / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    source = root / "README.md"
    source.write_text(
        "# demo",
        encoding="utf-8",
    )

    result = detect_monorepo(source)

    assert result.repository_path == root
    assert root in result.project_roots


def test_missing_directory_is_reported(tmp_path):
    missing = tmp_path / "missing"

    result = detect_monorepo(missing)

    assert result.is_monorepo is False
    assert result.repository_path == missing
    assert result.reason == "DIRECTORY_NOT_FOUND"


def test_multiple_ecosystems_are_detected(tmp_path):
    root = tmp_path / "repo"
    python_project = root / "python"
    node_project = root / "node"

    python_project.mkdir(parents=True)
    node_project.mkdir(parents=True)

    (python_project / "pyproject.toml").write_text(
        "[project]\nname='python'\n",
        encoding="utf-8",
    )
    (node_project / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    result = detect_monorepo(root)

    assert result.is_monorepo is True
    assert len(result.project_roots) == 2


def test_detection_does_not_modify_filesystem(tmp_path):
    root = tmp_path / "repo"
    app = root / "packages" / "app"

    app.mkdir(parents=True)
    (app / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = detect_monorepo(root)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.is_monorepo is False
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

    result = detect_monorepo(root)

    assert not marker.exists()
    assert result.is_monorepo is False


def test_result_is_immutable(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    result = detect_monorepo(root)

    try:
        result.is_monorepo = True
        changed = True
    except Exception:
        changed = False

    assert changed is False
    assert result.is_monorepo is False
