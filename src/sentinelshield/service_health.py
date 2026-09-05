from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceHealthResult:
    service: str
    active: bool
    enabled: bool
    healthy: bool


class SystemdServiceHealth:
    """
    Read-only systemd service health checker.

    Does not start, stop, restart, enable or disable services.
    """

    def __init__(self, service: str):
        if not isinstance(service, str):
            raise TypeError("service must be str")

        if not service.strip():
            raise ValueError("service must not be empty")

        self.service = service

    def _is_active(self) -> bool:
        result = subprocess.run(
            ["systemctl", "is-active", self.service],
            capture_output=True,
            text=True,
            check=False,
        )

        return (
            result.returncode == 0
            and result.stdout.strip() == "active"
        )

    def _is_enabled(self) -> bool:
        result = subprocess.run(
            ["systemctl", "is-enabled", self.service],
            capture_output=True,
            text=True,
            check=False,
        )

        return (
            result.returncode == 0
            and result.stdout.strip() == "enabled"
        )

    def check(self) -> ServiceHealthResult:
        active = self._is_active()
        enabled = self._is_enabled()

        return ServiceHealthResult(
            service=self.service,
            active=active,
            enabled=enabled,
            healthy=active and enabled,
        )
