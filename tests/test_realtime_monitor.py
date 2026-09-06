import sys
import time
from pathlib import Path

from sentinelshield.realtime_monitor import (
    FileChange,
    MonitorSnapshot,
    ProcessInfo,
    RealTimeProjectMonitor,
)


def test_snapshot_detects_project(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    (project / "main.py").write_text(
        "print('hello')\n",
        encoding="utf-8",
    )

    monitor = RealTimeProjectMonitor(project)
    snapshot = monitor.snapshot()

    assert isinstance(snapshot, MonitorSnapshot)
    assert snapshot.project_exists is True
    assert project / "main.py" in snapshot.files
    assert snapshot.fingerprint


def test_missing_project(tmp_path):
    monitor = RealTimeProjectMonitor(
        tmp_path / "missing"
    )

    snapshot = monitor.snapshot()

    assert snapshot.project_exists is False
    assert snapshot.files == ()


def test_initial_files_are_reported(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    file = project / "main.py"
    file.write_text(
        "print('hello')\n",
        encoding="utf-8",
    )

    monitor = RealTimeProjectMonitor(project)

    changes = monitor.poll()

    assert len(changes) == 1
    assert changes[0].path == file
    assert changes[0].change == "INITIAL"


def test_added_file_is_detected(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    monitor = RealTimeProjectMonitor(project)

    monitor.poll()

    file = project / "new.py"
    file.write_text(
        "print('new')\n",
        encoding="utf-8",
    )

    changes = monitor.poll()

    assert any(
        item.path == file
        and item.change == "ADDED"
        for item in changes
    )


def test_removed_file_is_detected(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    file = project / "old.py"
    file.write_text(
        "print('old')\n",
        encoding="utf-8",
    )

    monitor = RealTimeProjectMonitor(project)

    monitor.poll()

    file.unlink()

    changes = monitor.poll()

    assert any(
        item.path == file
        and item.change == "REMOVED"
        for item in changes
    )


def test_same_state_has_no_file_changes(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    file = project / "main.py"
    file.write_text(
        "print('hello')\n",
        encoding="utf-8",
    )

    monitor = RealTimeProjectMonitor(project)

    monitor.poll()
    changes = monitor.poll()

    assert changes == ()


def test_fingerprint_changes_after_file_modification(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    file = project / "main.py"

    file.write_text(
        "one\n",
        encoding="utf-8",
    )

    monitor = RealTimeProjectMonitor(project)

    first = monitor.snapshot()

    time.sleep(0.001)

    file.write_text(
        "two\n",
        encoding="utf-8",
    )

    second = monitor.snapshot()

    assert first.fingerprint != second.fingerprint


def test_process_snapshot_contains_current_process():
    monitor = RealTimeProjectMonitor(Path.cwd())

    snapshot = monitor.snapshot()

    assert isinstance(snapshot.processes, tuple)

    pids = {
        process.pid
        for process in snapshot.processes
    }

    assert any(
        process.pid > 0
        for process in snapshot.processes
    )


def test_process_info_is_valid():
    monitor = RealTimeProjectMonitor(Path.cwd())

    snapshot = monitor.snapshot()

    for process in snapshot.processes:
        assert isinstance(process, ProcessInfo)
        assert process.pid > 0
        assert isinstance(process.command, str)


def test_monitor_is_read_only(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    file = project / "main.py"
    original = "print('hello')\n"

    file.write_text(
        original,
        encoding="utf-8",
    )

    before = file.stat().st_mtime_ns

    monitor = RealTimeProjectMonitor(project)
    monitor.poll()
    monitor.snapshot()
    monitor.changes()

    after = file.stat().st_mtime_ns

    assert file.read_text(
        encoding="utf-8"
    ) == original

    assert before == after


def test_nested_files_are_detected(tmp_path):
    project = tmp_path / "demo"
    nested = project / "src" / "app"

    nested.mkdir(parents=True)

    file = nested / "main.py"
    file.write_text(
        "print('nested')\n",
        encoding="utf-8",
    )

    monitor = RealTimeProjectMonitor(project)
    snapshot = monitor.snapshot()

    assert file in snapshot.files


def test_path_is_resolved(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()

    monitor = RealTimeProjectMonitor(
        Path(project)
    )

    assert monitor.project_path == project.resolve()
