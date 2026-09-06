from pathlib import Path

from sentinelshield.project_orchestrator import ProjectOrchestrator
from sentinelshield.watch_command import (
    ProjectWatch,
    WatchTarget,
)


def test_watch_existing_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    watcher = ProjectWatch(
        ProjectOrchestrator()
    )

    result = watcher.add(
        "demo",
        project,
    )

    assert isinstance(result, WatchTarget)
    assert result.name == "demo"
    assert result.path == project.resolve()
    assert result.accepted is True


def test_watch_missing_project(tmp_path):
    project = tmp_path / "missing"

    result = ProjectWatch(
        ProjectOrchestrator()
    ).add(
        "missing",
        project,
    )

    assert result.accepted is False
    assert result.reason == "PROJECT_NOT_FOUND"


def test_watch_file_rejected(tmp_path):
    project = tmp_path / "file.txt"
    project.write_text(
        "test",
        encoding="utf-8",
    )

    result = ProjectWatch(
        ProjectOrchestrator()
    ).add(
        "file",
        project,
    )

    assert result.accepted is False
    assert result.reason == "NOT_A_DIRECTORY"


def test_watch_expands_relative_path(tmp_path, monkeypatch):
    project = tmp_path / "demo"
    project.mkdir()

    monkeypatch.chdir(tmp_path)

    result = ProjectWatch(
        ProjectOrchestrator()
    ).add(
        "demo",
        Path("demo"),
    )

    assert result.path == project.resolve()
    assert result.accepted is True


def test_watch_registers_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    orchestrator = ProjectOrchestrator()

    result = ProjectWatch(
        orchestrator
    ).add(
        "demo",
        project,
    )

    assert result.accepted is True

    inspection = orchestrator.inspect("demo")

    assert inspection.accepted is True


def test_watch_result_is_immutable(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    result = ProjectWatch(
        ProjectOrchestrator()
    ).add(
        "demo",
        project,
    )

    try:
        result.accepted = False
        assert False
    except AttributeError:
        pass


def test_watch_does_not_modify_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    marker = project / "main.py"
    marker.write_text(
        "print('hello')\n",
        encoding="utf-8",
    )

    before = marker.read_text(
        encoding="utf-8"
    )

    ProjectWatch(
        ProjectOrchestrator()
    ).add(
        "demo",
        project,
    )

    after = marker.read_text(
        encoding="utf-8"
    )

    assert before == after


def test_watch_multiple_projects(tmp_path):
    first = tmp_path / "one"
    second = tmp_path / "two"

    first.mkdir()
    second.mkdir()

    orchestrator = ProjectOrchestrator()
    watcher = ProjectWatch(orchestrator)

    one = watcher.add("one", first)
    two = watcher.add("two", second)

    assert one.accepted is True
    assert two.accepted is True

    assert orchestrator.inspect("one").accepted is True
    assert orchestrator.inspect("two").accepted is True
