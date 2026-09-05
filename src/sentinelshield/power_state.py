from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class PowerStateError(RuntimeError):
    """Raised when power-state information cannot be read safely."""


@dataclass(frozen=True)
class PowerState:
    source: str
    on_ac_power: bool | None
    battery_percent: float | None
    charging: bool | None


class PowerStateCheck:
    """
    Read-only laptop power-state checker.

    Supported Linux source:
        /sys/class/power_supply/

    This component never changes the power state.
    """

    POWER_SUPPLY_PATH = Path(
        "/sys/class/power_supply"
    )

    AC_TYPES = frozenset(
        {
            "Mains",
            "USB",
            "USB_C",
            "USB-C",
        }
    )

    def __init__(
        self,
        power_supply_path: Path | None = None,
    ) -> None:
        self.power_supply_path = (
            power_supply_path
            if power_supply_path is not None
            else self.POWER_SUPPLY_PATH
        )

    def check(self) -> PowerState:
        if not self.power_supply_path.exists():
            return PowerState(
                source="unavailable",
                on_ac_power=None,
                battery_percent=None,
                charging=None,
            )

        batteries = self._find_batteries()
        power_sources = self._find_power_sources()

        battery_percent = self._read_battery_percent(
            batteries
        )

        charging = self._read_charging_state(
            batteries
        )

        on_ac_power = self._read_ac_state(
            power_sources
        )

        if on_ac_power is True:
            source = "ac"
        elif battery_percent is not None:
            source = "battery"
        else:
            source = "unknown"

        return PowerState(
            source=source,
            on_ac_power=on_ac_power,
            battery_percent=battery_percent,
            charging=charging,
        )

    def is_valid(
        self,
        state: PowerState,
    ) -> bool:
        if not isinstance(state, PowerState):
            return False

        if state.source not in {
            "ac",
            "battery",
            "unknown",
            "unavailable",
        }:
            return False

        if state.battery_percent is not None:
            if not 0.0 <= state.battery_percent <= 100.0:
                return False

        if state.on_ac_power not in {
            True,
            False,
            None,
        }:
            return False

        if state.charging not in {
            True,
            False,
            None,
        }:
            return False

        return True

    def _find_batteries(self) -> list[Path]:
        if not self.power_supply_path.exists():
            return []

        result: list[Path] = []

        for path in self.power_supply_path.iterdir():
            if not path.is_dir():
                continue

            type_value = self._read_text(
                path / "type"
            )

            if type_value == "Battery":
                result.append(path)

        return result

    def _find_power_sources(self) -> list[Path]:
        if not self.power_supply_path.exists():
            return []

        result: list[Path] = []

        for path in self.power_supply_path.iterdir():
            if not path.is_dir():
                continue

            type_value = self._read_text(
                path / "type"
            )

            if type_value in self.AC_TYPES:
                result.append(path)

        return result

    def _read_battery_percent(
        self,
        batteries: list[Path],
    ) -> float | None:
        for battery in batteries:
            value = self._read_text(
                battery / "capacity"
            )

            if value is None:
                continue

            try:
                percent = float(value)
            except ValueError:
                continue

            if 0.0 <= percent <= 100.0:
                return percent

        return None

    def _read_charging_state(
        self,
        batteries: list[Path],
    ) -> bool | None:
        for battery in batteries:
            status = self._read_text(
                battery / "status"
            )

            if status is None:
                continue

            normalized = status.lower()

            if normalized in {
                "charging",
                "full",
            }:
                return True

            if normalized in {
                "discharging",
                "not charging",
            }:
                return False

        return None

    def _read_ac_state(
        self,
        power_sources: list[Path],
    ) -> bool | None:
        if not power_sources:
            return None

        for source in power_sources:
            online = self._read_text(
                source / "online"
            )

            if online == "1":
                return True

            if online == "0":
                continue

        return False

    @staticmethod
    def _read_text(
        path: Path,
    ) -> str | None:
        try:
            return path.read_text(
                encoding="utf-8"
            ).strip()
        except (
            OSError,
            UnicodeError,
        ):
            return None
