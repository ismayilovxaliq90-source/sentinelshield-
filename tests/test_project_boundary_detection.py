from pathlib import Path

from sentinelshield.project_boundary_detection import (
    ProjectBoundaryDetector,
    ProjectBoundaryResult,
    detect_project_boundary,
)


def test_valid_project_directory(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = detect_project_boundary(project)

    assert isinstance(
        result,
        ProjectBoundaryResult,
    )
    assert result.valid is True
    assert result.project_root == project
    assert result.boundary_root == project
    assert result.reason == "PROJECT_BOUNDARY_VALID"


def test_project_file_uses_parent_directory(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    source = project / "main.py"
    source.write_text(
        "print('x')",
        encoding="utf-8",
    )

    result = detect_project_boundary(source)

    assert result.valid is True
    assert result.project_root == project
    assert result.boundary_root == project


def test_git_directory_is_excluded(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    git = project / ".git"
    git.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert git in result.excluded_paths


def test_node_modules_is_excluded(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    node_modules = project / "node_modules"
    node_modules.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert node_modules in result.excluded_paths


def test_virtual_environment_is_excluded(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    venv = project / ".venv"
    venv.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert venv in result.excluded_paths


def test_build_directory_is_excluded(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    build = project / "build"
    build.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert build in result.excluded_paths


def test_dist_directory_is_excluded(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    dist = project / "dist"
    dist.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert dist in result.excluded_paths


def test_target_directory_is_excluded(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    target = project / "target"
    target.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert target in result.excluded_paths


def test_multiple_excluded_directories_are_detected(
    tmp_path,
):
    project = tmp_path / "project"
    project.mkdir()

    git = project / ".git"
    node_modules = project / "node_modules"
    venv = project / ".venv"

    git.mkdir()
    node_modules.mkdir()
    venv.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert git in result.excluded_paths
    assert node_modules in result.excluded_paths
    assert venv in result.excluded_paths


def test_regular_directories_are_not_excluded(
    tmp_path,
):
    project = tmp_path / "project"
    project.mkdir()

    src = project / "src"
    tests = project / "tests"

    src.mkdir()
    tests.mkdir()

    result = detect_project_boundary(project)

    assert result.valid is True
    assert src not in result.excluded_paths
    assert tests not in result.excluded_paths


def test_nested_excluded_directory_does_not_change_boundary(
    tmp_path,
):
    project = tmp_path / "project"
    project.mkdir()

    packages = project / "packages"
    nested_git = packages / ".git"

    nested_git.mkdir(parents=True)

    result = detect_project_boundary(project)

    assert result.valid is True
    assert result.boundary_root == project
    assert nested_git not in result.excluded_paths


def test_none_is_rejected():
    result = detect_project_boundary(None)

    assert result.valid is False
    assert result.project_root is None
    assert result.boundary_root is None
    assert result.reason == "PATH_IS_NONE"


def test_empty_string_is_rejected():
    result = detect_project_boundary("")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_whitespace_is_rejected():
    result = detect_project_boundary("   ")

    assert result.valid is False
    assert result.reason == "PATH_IS_EMPTY"


def test_null_character_is_rejected():
    result = detect_project_boundary(
        "/tmp/project\x00evil"
    )

    assert result.valid is False
    assert result.reason == (
        "NULL_CHARACTER_NOT_ALLOWED"
    )


def test_integer_is_rejected():
    result = detect_project_boundary(123)

    assert result.valid is False
    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_path_object_is_supported(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = ProjectBoundaryDetector().detect(
        Path(project)
    )

    assert result.valid is True
    assert result.project_root == project


def test_missing_directory_is_rejected(tmp_path):
    missing = tmp_path / "missing"

    result = detect_project_boundary(missing)

    assert result.valid is False
    assert result.project_root == missing
    assert result.reason == "DIRECTORY_NOT_FOUND"


def test_filesystem_is_not_modified(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "src").mkdir()
    (project / "README.md").write_text(
        "# project",
        encoding="utf-8",
    )

    before = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    result = detect_project_boundary(project)

    after = sorted(
        str(path.relative_to(tmp_path))
        for path in tmp_path.rglob("*")
    )

    assert result.valid is True
    assert before == after


def test_project_code_is_not_executed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    marker = tmp_path / "executed.txt"

    (project / "setup.py").write_text(
        f"open({str(marker)!r}, 'w').write('executed')",
        encoding="utf-8",
    )

    result = detect_project_boundary(project)

    assert result.valid is True
    assert not marker.exists()


def test_result_is_immutable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = detect_project_boundary(project)

    try:
        result.valid = False
        changed = True
    except Exception:
        changed = False

    assert changed is False
    assert result.valid is True


def test_excluded_paths_are_tuple(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / ".git").mkdir()
    (project / "node_modules").mkdir()

    result = detect_project_boundary(project)

    assert isinstance(
        result.excluded_paths,
        tuple,
    )
