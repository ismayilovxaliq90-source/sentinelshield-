from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class WatchAgentStatus:
    running: bool
    cycles: int


class WatchAgent:
    """
    Lightweight background watcher.

    It does not execute project code and does not modify
    the watched project.
    """

    def __init__(
        self,
        project_path: str | Path,
        check: Callable[[], object],
        interval: float = 5.0,
    ):
        self.project_path = Path(project_path).expanduser().resolve()
        self.check = check
        self.interval = interval

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._lock = threading.Lock()

    def start(self) -> WatchAgentStatus:
        if self._thread is not None and self._thread.is_alive():
            return self.status()

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run,
            name="sentinelshield-watch",
            daemon=True,
        )

        self._thread.start()

        return self.status()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.check()

            with self._lock:
                self._cycles += 1

            self._stop_event.wait(self.interval)

    def stop(self) -> WatchAgentStatus:
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(timeout=max(self.interval + 1, 2))

        return self.status()

    def status(self) -> WatchAgentStatus:
        with self._lock:
            cycles = self._cycles

        return WatchAgentStatus(
            running=(
                self._thread is not None
                and self._thread.is_alive()
            ),
            cycles=cycles,
        )
