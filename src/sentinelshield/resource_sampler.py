from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceSnapshot:
    cpu_percent: float
    ram_percent: float
    storage_percent: float


class ResourceSampler:
    """
    Reads current host resource usage.

    No enforcement or modification is performed here.
    """

    def __init__(self, psutil_module=None):
        if psutil_module is None:
            try:
                import psutil
            except ImportError as exc:
                raise RuntimeError(
                    "psutil is required for real resource sampling"
                ) from exc

            psutil_module = psutil

        self._psutil = psutil_module

    def sample(self) -> ResourceSnapshot:
        cpu = float(self._psutil.cpu_percent(interval=0.1))
        ram = float(self._psutil.virtual_memory().percent)

        disk = shutil.disk_usage("/")
        storage = (disk.used / disk.total) * 100.0

        return ResourceSnapshot(
            cpu_percent=cpu,
            ram_percent=ram,
            storage_percent=storage,
        )

    def sample_dict(self) -> dict[str, float]:
        snapshot = self.sample()

        return {
            "cpu_percent": snapshot.cpu_percent,
            "ram_percent": snapshot.ram_percent,
            "storage_percent": snapshot.storage_percent,
        }
