from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sentinelshield.monitoring_runtime import MonitoringRuntime


class ResourceGateRuntime:
    """
    Read-only resource gate.

    CPU, RAM and storage are checked against safe thresholds.
    """

    def __init__(
        self,
        cpu_limit: float = 80.0,
        ram_limit: float = 80.0,
        storage_limit: float = 90.0,
        output_path: str | Path = "runtime_data/resource_gate.json",
    ) -> None:
        if not 0 < cpu_limit <= 100:
            raise ValueError("invalid cpu_limit")

        if not 0 < ram_limit <= 100:
            raise ValueError("invalid ram_limit")

        if not 0 < storage_limit <= 100:
            raise ValueError("invalid storage_limit")

        self.cpu_limit = cpu_limit
        self.ram_limit = ram_limit
        self.storage_limit = storage_limit
        self.output_path = Path(output_path)

        self.monitor = MonitoringRuntime(
            output_path=Path(output_path).parent
            / "resource_status.json",
            interval=5.0,
        )

    def evaluate(self) -> dict:
        resources = self.monitor.run_once()

        cpu = float(
            resources["cpu"]["percent"]
        )
        ram = float(
            resources["ram"]["percent"]
        )
        storage = float(
            resources["storage"]["percent"]
        )

        failures = []

        if cpu > self.cpu_limit:
            failures.append("CPU_LIMIT")

        if ram > self.ram_limit:
            failures.append("RAM_LIMIT")

        if storage > self.storage_limit:
            failures.append("STORAGE_LIMIT")

        safe = not failures

        result = {
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "safe": safe,
            "status": (
                "SAFE"
                if safe
                else "BLOCKED"
            ),
            "limits": {
                "cpu_percent": self.cpu_limit,
                "ram_percent": self.ram_limit,
                "storage_percent": self.storage_limit,
            },
            "resources": resources,
            "failures": failures,
        }

        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.output_path.write_text(
            json.dumps(
                result,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        return result
