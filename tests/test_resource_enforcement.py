import pytest

from sentinelshield.resource_enforcement import (
    EnforcementDecision,
    EnforcementResult,
    ResourceEnforcement,
)


def test_normal_resources_are_allowed():
    result = ResourceEnforcement().evaluate(
        cpu_percent=20,
        ram_percent=30,
        storage_percent=40,
    )

    assert isinstance(result, EnforcementResult)
    assert result.decision == EnforcementDecision.ALLOW
    assert result.safe is True
    assert result.failures == ()


def test_cpu_limit_blocks():
    result = ResourceEnforcement().evaluate(
        cpu_percent=81,
        ram_percent=30,
        storage_percent=40,
    )

    assert result.decision == EnforcementDecision.BLOCK
    assert result.safe is False
    assert "CPU_LIMIT" in result.failures


def test_ram_limit_blocks():
    result = ResourceEnforcement().evaluate(
        cpu_percent=20,
        ram_percent=81,
        storage_percent=40,
    )

    assert result.decision == EnforcementDecision.BLOCK
    assert "RAM_LIMIT" in result.failures


def test_storage_limit_blocks():
    result = ResourceEnforcement().evaluate(
        cpu_percent=20,
        ram_percent=30,
        storage_percent=91,
    )

    assert result.decision == EnforcementDecision.BLOCK
    assert "STORAGE_LIMIT" in result.failures


def test_multiple_limits_are_reported():
    result = ResourceEnforcement().evaluate(
        cpu_percent=90,
        ram_percent=90,
        storage_percent=95,
    )

    assert result.decision == EnforcementDecision.BLOCK
    assert result.failures == (
        "CPU_LIMIT",
        "RAM_LIMIT",
        "STORAGE_LIMIT",
    )


def test_exact_cpu_limit_is_allowed():
    result = ResourceEnforcement().evaluate(
        cpu_percent=80,
        ram_percent=80,
        storage_percent=90,
    )

    assert result.decision == EnforcementDecision.ALLOW


def test_custom_limits_are_respected():
    result = ResourceEnforcement().evaluate(
        cpu_percent=61,
        ram_percent=41,
        storage_percent=71,
        cpu_limit=60,
        ram_limit=40,
        storage_limit=70,
    )

    assert result.decision == EnforcementDecision.BLOCK
    assert result.failures == (
        "CPU_LIMIT",
        "RAM_LIMIT",
        "STORAGE_LIMIT",
    )


def test_invalid_resource_type_is_rejected():
    with pytest.raises(TypeError):
        ResourceEnforcement().evaluate(
            cpu_percent="20",
            ram_percent=30,
            storage_percent=40,
        )


def test_invalid_resource_range_is_rejected():
    with pytest.raises(ValueError):
        ResourceEnforcement().evaluate(
            cpu_percent=101,
            ram_percent=30,
            storage_percent=40,
        )


def test_negative_resource_is_rejected():
    with pytest.raises(ValueError):
        ResourceEnforcement().evaluate(
            cpu_percent=-1,
            ram_percent=30,
            storage_percent=40,
        )


def test_invalid_limit_type_is_rejected():
    with pytest.raises(TypeError):
        ResourceEnforcement().evaluate(
            cpu_percent=20,
            ram_percent=30,
            storage_percent=40,
            cpu_limit="80",
        )


def test_zero_limit_is_rejected():
    with pytest.raises(ValueError):
        ResourceEnforcement().evaluate(
            cpu_percent=20,
            ram_percent=30,
            storage_percent=40,
            cpu_limit=0,
        )


def test_limit_above_100_is_rejected():
    with pytest.raises(ValueError):
        ResourceEnforcement().evaluate(
            cpu_percent=20,
            ram_percent=30,
            storage_percent=40,
            storage_limit=101,
        )


def test_reason_for_allow_is_recorded():
    result = ResourceEnforcement().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    assert result.reason == (
        "resources within configured limits"
    )


def test_reason_for_block_is_recorded():
    result = ResourceEnforcement().evaluate(
        cpu_percent=90,
        ram_percent=10,
        storage_percent=10,
    )

    assert result.reason == (
        "resource limit exceeded"
    )


def test_require_allowed_returns_result_when_safe():
    result = ResourceEnforcement().require_allowed(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    assert result.decision == EnforcementDecision.ALLOW


def test_require_allowed_blocks_unsafe_state():
    with pytest.raises(PermissionError):
        ResourceEnforcement().require_allowed(
            cpu_percent=90,
            ram_percent=10,
            storage_percent=10,
        )


def test_enforcement_is_deterministic():
    enforcement = ResourceEnforcement()

    first = enforcement.evaluate(
        cpu_percent=25,
        ram_percent=35,
        storage_percent=45,
    )

    second = enforcement.evaluate(
        cpu_percent=25,
        ram_percent=35,
        storage_percent=45,
    )

    assert first == second


def test_result_is_immutable():
    result = ResourceEnforcement().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    with pytest.raises(AttributeError):
        result.safe = False
