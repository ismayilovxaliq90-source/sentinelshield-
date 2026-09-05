from pathlib import Path

import pytest

from sentinelshield.project_health import (
    ProjectHealth,
    ProjectHealthChecker,
)
from sentinelshield.project_registry import ProjectRecord


def make_project(path: Path, name="demo"):
    return ProjectRecord(
        name=name,
        path=str(path.resolve()),
    )


def test_healthy_directory(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    (project / "main.py").write_text(
        "print('ok')\n",
        encoding="utf-8",
    )

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    assert isinstance(result, ProjectHealth)
    assert result.healthy is True
    assert result.exists is True
    assert result.is_directory is True
    assert result.readable is True
    assert result.python_files == 1
    assert result.reasons == ("OK",)


def test_healthy_project_with_multiple_python_files(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    (project / "main.py").write_text("", encoding="utf-8")
    (project / "worker.py").write_text("", encoding="utf-8")
    (project / "notes.txt").write_text("", encoding="utf-8")

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    assert result.healthy is True
    assert result.python_files == 2


def test_missing_path(tmp_path):
    project = tmp_path / "missing"

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    assert result.healthy is False
    assert result.exists is False
    assert "PATH_NOT_FOUND" in result.reasons


def test_file_instead_of_directory(tmp_path):
    project = tmp_path / "not_directory"
    project.write_text("x", encoding="utf-8")

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    assert result.healthy is False
    assert result.exists is True
    assert result.is_directory is False
    assert "NOT_DIRECTORY" in result.reasons


def test_empty_project_is_still_healthy(tmp_path):
    project = tmp_path / "empty"
    project.mkdir()

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    assert result.healthy is True
    assert result.python_files == 0


def test_non_project_record_rejected():
    with pytest.raises(TypeError):
        ProjectHealthChecker().check(object())


def test_health_is_immutable(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    with pytest.raises(AttributeError):
        result.healthy = False


def test_require_healthy_accepts_healthy_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    ProjectHealthChecker().require_healthy(result)


def test_require_healthy_rejects_unhealthy_project(tmp_path):
    project = tmp_path / "missing"

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    with pytest.raises(RuntimeError):
        ProjectHealthChecker().require_healthy(result)


def test_python_scan_is_recursive(tmp_path):
    project = tmp_path / "demo"
    nested = project / "src" / "pkg"

    nested.mkdir(parents=True)

    (nested / "app.py").write_text(
        "",
        encoding="utf-8",
    )

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    assert result.healthy is True
    assert result.python_files == 1


def test_non_python_files_do_not_count(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    (project / "README.md").write_text(
        "demo",
        encoding="utf-8",
    )

    result = ProjectHealthChecker().check(
        make_project(project)
    )

    assert result.python_files == 0
    assert result.healthy is True
