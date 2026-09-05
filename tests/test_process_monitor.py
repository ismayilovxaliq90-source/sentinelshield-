import subprocess
import sys

import pytest

from sentinelshield.process_monitor import (
    ProcessMonitor,
    ProcessMonitorError,
)


@pytest.fixture
def monitor():
    return ProcessMonitor()


def test_current_pid_is_positive(monitor):
    pid = monitor.current_pid()

    assert isinstance(pid, int)
    assert pid > 0


def test_poll_interval_must_be_positive():
    with pytest.raises(ValueError):
        ProcessMonitor(poll_interval=0)

    with pytest.raises(ValueError):
        ProcessMonitor(poll_interval=-1)


def test_running_process_is_detected(monitor):
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(0.2)",
        ]
    )

    try:
        snapshot = monitor.snapshot(
            process,
            [
                sys.executable,
                "-c",
                "import time; time.sleep(0.2)",
            ],
        )

        assert snapshot.pid == process.pid
        assert snapshot.running is True
        assert snapshot.return_code is None
        assert snapshot.command[0] == sys.executable
    finally:
        process.terminate()
        process.wait()


def test_finished_process_is_detected(monitor):
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "raise SystemExit(7)",
        ]
    )

    return_code = process.wait()

    assert return_code == 7

    snapshot = monitor.snapshot(process)

    assert snapshot.pid == process.pid
    assert snapshot.running is False
    assert snapshot.return_code == 7


def test_successful_process_return_code(monitor):
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "pass",
        ]
    )

    return_code = monitor.wait(
        process,
        timeout=2,
    )

    assert return_code == 0

    snapshot = monitor.snapshot(process)

    assert snapshot.running is False
    assert snapshot.return_code == 0


def test_is_running_returns_true_for_active_process(monitor):
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(0.2)",
        ]
    )

    try:
        assert monitor.is_running(process) is True
    finally:
        process.terminate()
        process.wait()


def test_is_running_returns_false_for_finished_process(monitor):
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "pass",
        ]
    )

    process.wait()

    assert monitor.is_running(process) is False


def test_wait_timeout_is_reported(monitor):
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(1)",
        ]
    )

    try:
        with pytest.raises(ProcessMonitorError):
            monitor.wait(
                process,
                timeout=0.01,
            )
    finally:
        process.terminate()
        process.wait()


def test_invalid_process_is_rejected_by_snapshot(monitor):
    with pytest.raises(ProcessMonitorError):
        monitor.snapshot("not-a-process")


def test_invalid_process_is_rejected_by_is_running(monitor):
    with pytest.raises(ProcessMonitorError):
        monitor.is_running("not-a-process")


def test_invalid_process_is_rejected_by_wait(monitor):
    with pytest.raises(ProcessMonitorError):
        monitor.wait("not-a-process")
