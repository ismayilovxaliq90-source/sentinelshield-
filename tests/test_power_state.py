from pathlib import Path

from sentinelshield.power_state import (
    PowerState,
    PowerStateCheck,
)


def create_supply(
    root: Path,
    name: str,
    type_value: str,
    files: dict[str, str],
) -> None:
    device = root / name
    device.mkdir(parents=True)

    (device / "type").write_text(
        type_value,
        encoding="utf-8",
    )

    for filename, value in files.items():
        (device / filename).write_text(
            value,
            encoding="utf-8",
        )


def test_missing_power_supply_is_safe(tmp_path):
    checker = PowerStateCheck(
        tmp_path / "missing"
    )

    state = checker.check()

    assert state.source == "unavailable"
    assert state.on_ac_power is None
    assert state.battery_percent is None
    assert state.charging is None
    assert checker.is_valid(state)


def test_ac_power_is_detected(tmp_path):
    root = tmp_path / "power_supply"
    root.mkdir()

    create_supply(
        root,
        "AC",
        "Mains",
        {
            "online": "1",
        },
    )

    checker = PowerStateCheck(root)

    state = checker.check()

    assert state.source == "ac"
    assert state.on_ac_power is True
    assert checker.is_valid(state)


def test_battery_power_is_detected(tmp_path):
    root = tmp_path / "power_supply"
    root.mkdir()

    create_supply(
        root,
        "BAT0",
        "Battery",
        {
            "capacity": "72",
            "status": "Discharging",
        },
    )

    checker = PowerStateCheck(root)

    state = checker.check()

    assert state.source == "battery"
    assert state.on_ac_power is None
    assert state.battery_percent == 72.0
    assert state.charging is False


def test_charging_battery_is_detected(tmp_path):
    root = tmp_path / "power_supply"
    root.mkdir()

    create_supply(
        root,
        "BAT0",
        "Battery",
        {
            "capacity": "88",
            "status": "Charging",
        },
    )

    checker = PowerStateCheck(root)

    state = checker.check()

    assert state.battery_percent == 88.0
    assert state.charging is True


def test_full_battery_is_treated_as_charged(tmp_path):
    root = tmp_path / "power_supply"
    root.mkdir()

    create_supply(
        root,
        "BAT0",
        "Battery",
        {
            "capacity": "100",
            "status": "Full",
        },
    )

    checker = PowerStateCheck(root)

    state = checker.check()

    assert state.battery_percent == 100.0
    assert state.charging is True


def test_battery_percentage_is_bounded(tmp_path):
    root = tmp_path / "power_supply"
    root.mkdir()

    create_supply(
        root,
        "BAT0",
        "Battery",
        {
            "capacity": "55",
            "status": "Discharging",
        },
    )

    checker = PowerStateCheck(root)

    state = checker.check()

    assert 0.0 <= state.battery_percent <= 100.0


def test_unknown_state_is_valid(tmp_path):
    root = tmp_path / "power_supply"
    root.mkdir()

    checker = PowerStateCheck(root)

    state = checker.check()

    assert state.source == "unknown"
    assert checker.is_valid(state)


def test_invalid_battery_percentage_is_rejected():
    checker = PowerStateCheck()

    state = PowerState(
        source="battery",
        on_ac_power=False,
        battery_percent=150.0,
        charging=False,
    )

    assert checker.is_valid(state) is False


def test_negative_battery_percentage_is_rejected():
    checker = PowerStateCheck()

    state = PowerState(
        source="battery",
        on_ac_power=False,
        battery_percent=-1.0,
        charging=False,
    )

    assert checker.is_valid(state) is False


def test_invalid_source_is_rejected():
    checker = PowerStateCheck()

    state = PowerState(
        source="danger",
        on_ac_power=None,
        battery_percent=None,
        charging=None,
    )

    assert checker.is_valid(state) is False


def test_non_power_state_is_rejected():
    checker = PowerStateCheck()

    assert checker.is_valid(
        "invalid"
    ) is False
