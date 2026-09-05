import pytest

from sentinelshield.monitoring_policy_pipeline import (
    MonitoringPolicyPipeline,
    ResourceSnapshot,
    build_pipeline,
)
from sentinelshield.policy import PolicyEngine, PolicyMode, SentinelPolicy
from sentinelshield.resource_enforcement import EnforcementDecision


def test_normal_resources_are_allowed():
    result = build_pipeline().evaluate(
        cpu_percent=20,
        ram_percent=30,
        storage_percent=40,
    )

    assert result.allowed is True
    assert result.blocked is False
    assert result.enforcement.decision == EnforcementDecision.ALLOW


def test_cpu_limit_blocks():
    result = build_pipeline().evaluate(
        cpu_percent=81,
        ram_percent=30,
        storage_percent=40,
    )

    assert result.blocked is True
    assert "CPU_LIMIT" in result.enforcement.failures


def test_ram_limit_blocks():
    result = build_pipeline().evaluate(
        cpu_percent=30,
        ram_percent=81,
        storage_percent=40,
    )

    assert result.blocked is True
    assert "RAM_LIMIT" in result.enforcement.failures


def test_storage_limit_blocks():
    result = build_pipeline().evaluate(
        cpu_percent=30,
        ram_percent=40,
        storage_percent=91,
    )

    assert result.blocked is True
    assert "STORAGE_LIMIT" in result.enforcement.failures


def test_multiple_limits_block():
    result = build_pipeline().evaluate(
        cpu_percent=90,
        ram_percent=90,
        storage_percent=95,
    )

    assert result.blocked is True
    assert "CPU_LIMIT" in result.enforcement.failures
    assert "RAM_LIMIT" in result.enforcement.failures
    assert "STORAGE_LIMIT" in result.enforcement.failures


def test_exact_limits_are_allowed():
    result = build_pipeline().evaluate(
        cpu_percent=80,
        ram_percent=80,
        storage_percent=90,
    )

    assert result.allowed is True
    assert result.blocked is False


def test_custom_policy_limits_are_used():
    policy = SentinelPolicy(
        cpu_limit_percent=50,
        ram_limit_percent=60,
        storage_limit_percent=70,
    )

    pipeline = build_pipeline(policy)

    allowed = pipeline.evaluate(
        cpu_percent=49,
        ram_percent=59,
        storage_percent=69,
    )

    blocked = pipeline.evaluate(
        cpu_percent=51,
        ram_percent=59,
        storage_percent=69,
    )

    assert allowed.allowed is True
    assert blocked.blocked is True
    assert "CPU_LIMIT" in blocked.enforcement.failures


def test_snapshot_is_preserved():
    result = build_pipeline().evaluate(
        cpu_percent=11.5,
        ram_percent=22.5,
        storage_percent=33.5,
    )

    assert isinstance(result.snapshot, ResourceSnapshot)
    assert result.snapshot.cpu_percent == 11.5
    assert result.snapshot.ram_percent == 22.5
    assert result.snapshot.storage_percent == 33.5


def test_policy_mode_is_reported():
    result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    assert result.policy_mode == "ENFORCE"


def test_pipeline_is_deterministic():
    pipeline = build_pipeline()

    a = pipeline.evaluate(
        cpu_percent=55,
        ram_percent=60,
        storage_percent=70,
    )
    b = pipeline.evaluate(
        cpu_percent=55,
        ram_percent=60,
        storage_percent=70,
    )

    assert a == b


def test_monitor_mode_does_not_block():
    policy = SentinelPolicy(mode=PolicyMode.MONITOR)
    pipeline = build_pipeline(policy)

    result = pipeline.evaluate(
        cpu_percent=99,
        ram_percent=99,
        storage_percent=99,
    )

    assert result.policy_mode == "MONITOR"
    assert result.allowed is True
    assert result.blocked is False
    assert result.enforcement.decision == EnforcementDecision.ALLOW
    assert result.enforcement.safe is True
    assert "MONITOR_ONLY" in result.enforcement.reason
    assert len(result.enforcement.failures) > 0


def test_policy_engine_can_be_injected():
    policy = SentinelPolicy(cpu_limit_percent=55)
    engine = PolicyEngine(policy)

    pipeline = MonitoringPolicyPipeline(policy_engine=engine)

    result = pipeline.evaluate(
        cpu_percent=56,
        ram_percent=10,
        storage_percent=10,
    )

    assert result.blocked is True


@pytest.mark.parametrize(
    "cpu,ram,storage",
    [
        (0, 0, 0),
        (1, 1, 1),
        (50, 50, 50),
        (79.9, 79.9, 89.9),
    ],
)
def test_safe_values(cpu, ram, storage):
    result = build_pipeline().evaluate(
        cpu_percent=cpu,
        ram_percent=ram,
        storage_percent=storage,
    )
    assert result.allowed is True


def test_pipeline_returns_explicit_booleans():
    result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    assert isinstance(result.allowed, bool)
    assert isinstance(result.blocked, bool)


def test_allowed_and_blocked_are_mutually_exclusive():
    result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    assert result.allowed != result.blocked
