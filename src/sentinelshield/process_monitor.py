from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Sequence


class ProcessMonitorError(RuntimeError):
    """Raised when process monitoring cannot be completed safely."""


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    running: bool
    return_code: int | None
    command: tuple[str, ...]


class ProcessMonitor:
    """
    Minimal process observation layer.

    This monitor does not start processes and does not terminate them.
    It only observes a process supplied by the caller.
    """

    def __init__(self, poll_interval: float = 0.05) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")

        self.poll_interval = poll_interval

    def snapshot(
        self,
        process: subprocess.Popen[str],
        command: Sequence[str] | None = None,
    ) -> ProcessSnapshot:
        if not isinstance(process, subprocess.Popen):
            raise ProcessMonitorError(
                "process must be a subprocess.Popen instance"
            )

        return_code = process.poll()

        if command is None:
            command_tuple: tuple[str, ...] = ()
        else:
            command_tuple = tuple(command)

        return ProcessSnapshot(
            pid=process.pid,
            running=return_code is None,
            return_code=return_code,
            command=command_tuple,
        )

    def is_running(
        self,
        process: subprocess.Popen[str],
    ) -> bool:
        if not isinstance(process, subprocess.Popen):
            raise ProcessMonitorError(
                "process must be a subprocess.Popen instance"
            )

        return process.poll() is None

    def wait(
        self,
        process: subprocess.Popen[str],
        timeout: float | None = None,
    ) -> int:
        if not isinstance(process, subprocess.Popen):
            raise ProcessMonitorError(
                "process must be a subprocess.Popen instance"
            )

        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise ProcessMonitorError(
                f"process did not finish within timeout: {timeout}"
            ) from exc

    @staticmethod
    def current_pid() -> int:
        return os.getpid()
