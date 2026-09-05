from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from sentinelshield.cpu_monitor import CPUMonitor
from sentinelshield.ram_monitor import RAMMonitor
from sentinelshield.storage_monitor import StorageMonitor


class MonitoringRuntime:
    """
    Continuous read-only resource monitoring layer.

    Reads CPU, RAM and storage information and writes a
    structured status snapshot.
    """

    def __init__(
        self,
        output_path: str | Path = "runtime_data/resource_status.json",
        interval: float = 5.0,
    ) -> None:
        if interval <= 0:
            raise ValueError(
                "interval must be greater than zero"
            )

        self.output_path = Path(output_path)
        self.interval = interval

        self.cpu = CPUMonitor()
        self.ram = RAMMonitor()
        self.storage = StorageMonitor()

        self.running = True

    def stop(self) -> None:
        self.running = False

    def collect(self) -> dict:
        cpu_reading = self.cpu.read()
        ram_reading = self.ram.read()
        storage_reading = self.storage.read()

        return {
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "cpu": {
                "percent": cpu_reading.percent,
                "cpu_count": cpu_reading.cpu_count,
            },
            "ram": {
                "percent": ram_reading.usage_percent,
            },
            "storage": {
                "percent": storage_reading.usage_percent,
            },
        }

    def write_status(self, data: dict) -> None:
        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.output_path.write_text(
            json.dumps(
                data,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def run_once(self) -> dict:
        data = self.collect()
        self.write_status(data)
        return data

    def run(self) -> None:
        while self.running:
            self.run_once()
            time.sleep(self.interval)
