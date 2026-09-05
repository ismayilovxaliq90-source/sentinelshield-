from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PolicyMode(str, Enum):
    ENFORCE = "ENFORCE"
    MONITOR = "MONITOR"


@dataclass(frozen=True)
class SentinelPolicy:
    mode: PolicyMode = PolicyMode.ENFORCE
    cpu_limit_percent: float = 80.0
    ram_limit_percent: float = 80.0
    storage_limit_percent: float = 90.0
    check_interval_seconds: float = 5.0
    command_timeout_seconds: float = 30.0
    max_processes: int = 100
    max_log_size_mb: int = 100
    recovery_enabled: bool = True
    emergency_stop_enabled: bool = True

    def __post_init__(self):
        if not isinstance(self.mode, PolicyMode):
            raise TypeError("mode must be PolicyMode")

        for name, value in (
            ("cpu_limit_percent", self.cpu_limit_percent),
            ("ram_limit_percent", self.ram_limit_percent),
            ("storage_limit_percent", self.storage_limit_percent),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")
            if value <= 0 or value > 100:
                raise ValueError(f"{name} must be > 0 and <= 100")

        for name, value in (
            ("check_interval_seconds", self.check_interval_seconds),
            ("command_timeout_seconds", self.command_timeout_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")
            if value <= 0:
                raise ValueError(f"{name} must be > 0")

        for name, value in (
            ("max_processes", self.max_processes),
            ("max_log_size_mb", self.max_log_size_mb),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be int")
            if value <= 0:
                raise ValueError(f"{name} must be > 0")

        if not isinstance(self.recovery_enabled, bool):
            raise TypeError("recovery_enabled must be bool")

        if not isinstance(self.emergency_stop_enabled, bool):
            raise TypeError("emergency_stop_enabled must be bool")

    @property
    def resource_limits(self):
        return {
            "cpu": float(self.cpu_limit_percent),
            "ram": float(self.ram_limit_percent),
            "storage": float(self.storage_limit_percent),
        }

    def as_dict(self):
        return {
            "mode": self.mode.value,
            "cpu_limit_percent": self.cpu_limit_percent,
            "ram_limit_percent": self.ram_limit_percent,
            "storage_limit_percent": self.storage_limit_percent,
            "check_interval_seconds": self.check_interval_seconds,
            "command_timeout_seconds": self.command_timeout_seconds,
            "max_processes": self.max_processes,
            "max_log_size_mb": self.max_log_size_mb,
            "recovery_enabled": self.recovery_enabled,
            "emergency_stop_enabled": self.emergency_stop_enabled,
        }


class PolicyEngine:
    def __init__(self, policy: SentinelPolicy | None = None):
        self._policy = policy or SentinelPolicy()

    @property
    def policy(self):
        return self._policy

    def replace(self, policy: SentinelPolicy):
        if not isinstance(policy, SentinelPolicy):
            raise TypeError("policy must be SentinelPolicy")
        self._policy = policy
        return self._policy

    def limits(self):
        return self._policy.resource_limits
