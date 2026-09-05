import os
import platform
import socket
from pathlib import Path


def _read_first_available(paths: list[str]) -> str | None:
    for path in paths:
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            continue

        if value:
            return value

    return None


def detect_host_identity() -> dict:
    machine_id = _read_first_available(
        [
            "/etc/machine-id",
            "/var/lib/dbus/machine-id",
        ]
    )

    boot_id = _read_first_available(
        [
            "/proc/sys/kernel/random/boot_id",
        ]
    )

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "machine_id": machine_id,
        "boot_id": boot_id,
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "os": platform.system(),
        "container_hint": os.environ.get("container"),
    }
