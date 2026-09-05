import pytest

from sentinelshield.thermal_gate import (
    ThermalGate,
    ThermalLimitExceeded,
    ThermalReadingInvalid,
)


def test_allows_temperature_below_limit():
    gate = ThermalGate(maximum_c=85)

    decision = gate.evaluate(70)

    assert decision.allowed is True
    assert decision.temperature_c == 70
    assert decision.limit_c == 85
    assert decision.reason == "THERMAL OK"


def test_allows_temperature_just_below_limit():
    gate = ThermalGate(maximum_c=85)

    decision = gate.evaluate(84.9)

    assert decision.allowed is True


def test_blocks_temperature_at_limit():
    gate = ThermalGate(maximum_c=85)

    decision = gate.evaluate(85)

    assert decision.allowed is False
    assert decision.reason == "THERMAL LIMIT EXCEEDED"


def test_blocks_temperature_above_limit():
    gate = ThermalGate(maximum_c=85)

    decision = gate.evaluate(95)

    assert decision.allowed is False
    assert decision.temperature_c == 95
    assert decision.reason == "THERMAL LIMIT EXCEEDED"


def test_enforce_raises_when_temperature_is_too_high():
    gate = ThermalGate(maximum_c=85)

    with pytest.raises(ThermalLimitExceeded):
        gate.enforce(90)


def test_enforce_allows_safe_temperature():
    gate = ThermalGate(maximum_c=85)

    decision = gate.enforce(60)

    assert decision.allowed is True


def test_missing_temperature_is_blocked():
    gate = ThermalGate(maximum_c=85)

    decision = gate.evaluate(None)

    assert decision.allowed is False
    assert decision.reason == "THERMAL READING UNAVAILABLE"


def test_invalid_temperature_is_blocked():
    gate = ThermalGate(maximum_c=85)

    decision = gate.evaluate("invalid")

    assert decision.allowed is False
    assert decision.reason == "THERMAL READING INVALID"


def test_nan_temperature_is_blocked():
    gate = ThermalGate(maximum_c=85)

    decision = gate.evaluate(float("nan"))

    assert decision.allowed is False
    assert decision.reason == "THERMAL READING INVALID"


def test_check_returns_boolean():
    gate = ThermalGate(maximum_c=85)

    assert gate.check(50) is True
    assert gate.check(90) is False


def test_custom_limit():
    gate = ThermalGate(maximum_c=75)

    assert gate.check(74.9) is True
    assert gate.check(75) is False


def test_invalid_limit_is_rejected():
    with pytest.raises(ValueError):
        ThermalGate(maximum_c=0)
