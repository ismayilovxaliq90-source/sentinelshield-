from pathlib import Path

import pytest

from sentinelshield.project_orchestrator import (
    OrchestrationResult,
    ProjectOrchestrator,
)


def test_healthy_project_is_accepted(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    result = orchestrator.inspect("demo")

    assert isinstance(result, OrchestrationResult)
    assert result.accepted is True
    assert result.reason == "READY"
    assert result.health.healthy is True


def test_missing_project_is_rejected(tmp_path):
    project = tmp_path / "missing"

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(tmp_path),
    )

    # Change registry record through a fresh orchestrator
    # to test health failure safely.
    orchestrator.registry.unregister("demo")

    with pytest.raises(FileNotFoundError):
        orchestrator.register(
            name="demo",
            path=str(project),
        )


def test_disabled_project_is_rejected(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
        enabled=False,
    )

    result = orchestrator.inspect("demo")

    assert result.accepted is False
    assert result.reason == "PROJECT_DISABLED"
    assert result.health.healthy is True


def test_unknown_project_rejected(tmp_path):
    orchestrator = ProjectOrchestrator()

    with pytest.raises(KeyError):
        orchestrator.inspect("unknown")


def test_ready_returns_true_for_healthy_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    assert orchestrator.ready("demo") is True


def test_list_ready_only_returns_enabled_healthy_projects(tmp_path):
    healthy = tmp_path / "healthy"
    disabled = tmp_path / "disabled"

    healthy.mkdir()
    disabled.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="healthy",
        path=str(healthy),
    )

    orchestrator.register(
        name="disabled",
        path=str(disabled),
        enabled=False,
    )

    ready = orchestrator.list_ready()

    assert len(ready) == 1
    assert ready[0].project == "healthy"
    assert ready[0].accepted is True


def test_relative_path_is_rejected(tmp_path):
    orchestrator = ProjectOrchestrator()

    with pytest.raises(ValueError):
        orchestrator.register(
            name="demo",
            path="relative/path",
        )


def test_file_path_is_rejected(tmp_path):
    file_path = tmp_path / "project.txt"
    file_path.write_text("x", encoding="utf-8")

    orchestrator = ProjectOrchestrator()

    with pytest.raises(NotADirectoryError):
        orchestrator.register(
            name="demo",
            path=str(file_path),
        )


def test_duplicate_project_is_rejected(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    with pytest.raises(ValueError):
        orchestrator.register(
            name="demo",
            path=str(project),
        )


def test_orchestration_result_is_immutable(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    result = orchestrator.inspect("demo")

    with pytest.raises(AttributeError):
        result.accepted = False


def test_python_project_is_accepted(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    (project / "main.py").write_text(
        "print('test')\n",
        encoding="utf-8",
    )

    orchestrator = ProjectOrchestrator()

    orchestrator.register(
        name="demo",
        path=str(project),
    )

    result = orchestrator.inspect("demo")

    assert result.accepted is True
    assert result.health.python_files == 1
