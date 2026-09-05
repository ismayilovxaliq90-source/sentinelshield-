from __future__ import annotations

import json
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from sentinelshield.final_health_check import FinalHealthCheck
from sentinelshield.monitoring_runtime import MonitoringRuntime
from sentinelshield.resource_gate_runtime import ResourceGateRuntime


RUNNING = True


def _stop_handler(signum, frame):
    global RUNNING
    RUNNING = False


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def main(interval: float = 5.0) -> int:
    global RUNNING

    signal.signal(
        signal.SIGINT,
        _stop_handler,
    )
    signal.signal(
        signal.SIGTERM,
        _stop_handler,
    )

    data_dir = Path(
        "runtime_data"
    ).resolve()

    data_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    service_status = (
        data_dir / "service_status.json"
    )

    monitor = MonitoringRuntime(
        output_path=(
            data_dir / "resource_status.json"
        ),
        interval=interval,
    )

    gate = ResourceGateRuntime(
        cpu_limit=80.0,
        ram_limit=80.0,
        storage_limit=90.0,
        output_path=(
            data_dir / "resource_gate.json"
        ),
    )

    print(
        "=" * 60
    )
    print(
        " SENTINELSHIELD CONTINUOUS SAFE RUNTIME"
    )
    print(
        "=" * 60
    )
    print(
        "CPU LIMIT: 80.0%"
    )
    print(
        "RAM LIMIT: 80.0%"
    )
    print(
        "STORAGE LIMIT: 90.0%"
    )
    print(
        "INTERVAL:",
        interval,
        "seconds",
    )
    print()

    while RUNNING:
        try:
            health = (
                FinalHealthCheck().check()
            )

            resources = monitor.run_once()
            gate_result = gate.evaluate()

            healthy = bool(
                health.healthy
            )

            safe = bool(
                gate_result["safe"]
            )

            if healthy and safe:
                status = "RUNNING"
                message = (
                    "Core healthy; "
                    "resource monitoring active; "
                    "resource gate SAFE"
                )
            elif healthy and not safe:
                status = "BLOCKED"
                message = (
                    "Resource gate blocked execution"
                )
            else:
                status = "UNHEALTHY"
                message = (
                    "Core health check failed"
                )

            payload = {
                "timestamp_utc": (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                ),
                "status": status,
                "healthy": healthy,
                "safe": safe,
                "message": message,
                "resources": resources,
                "resource_gate": gate_result,
            }

            _write_json(
                service_status,
                payload,
            )

            print(
                datetime.now().strftime(
                    "%H:%M:%S"
                ),
                "|",
                status,
                "| CPU="
                f"{resources['cpu']['percent']:.1f}%",
                "| RAM="
                f"{resources['ram']['percent']:.1f}%",
                "| STORAGE="
                f"{resources['storage']['percent']:.1f}%",
                flush=True,
            )

        except Exception as exc:
            payload = {
                "timestamp_utc": (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                ),
                "status": "ERROR",
                "healthy": False,
                "safe": False,
                "message": (
                    f"{type(exc).__name__}: {exc}"
                ),
            }

            _write_json(
                service_status,
                payload,
            )

            print(
                datetime.now().strftime(
                    "%H:%M:%S"
                ),
                "| ERROR |",
                type(exc).__name__,
                str(exc),
                flush=True,
            )

        time.sleep(interval)

    _write_json(
        service_status,
        {
            "timestamp_utc": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),
            "status": "STOPPED",
            "healthy": False,
            "safe": False,
            "message": (
                "SentinelShield service stopped"
            ),
        },
    )

    print(
        "SENTINELSHIELD SERVICE: STOPPED"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
