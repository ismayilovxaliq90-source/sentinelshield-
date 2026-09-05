from types import SimpleNamespace

import pytest

from sentinelshield.action_controller import ActionDecision
from sentinelshield.monitoring_policy_pipeline import build_pipeline
from sentinelshield.safe_execution_gateway import (
    GatewayResult,
    SafeExecutionGateway,
)


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def run(self, command, timeout=30.0):
        self.calls.append((command, timeout))
        return SimpleNamespace(
            returncode=0,
            stdout="OK",
            stderr="",
        )


def test_allowed_action_executes():
    pipeline = build_pipeline()

    pipeline_result = pipeline.evaluate(
        cpu_percent=20,
        ram_percent=30,
        storage_percent=40,
    )

    executor = FakeExecutor()

    result = SafeExecutionGateway(
        executor=executor,
    ).execute(
        pipeline_result,
        action="HEALTH_CHECK",
        command=["printf", "hello"],
    )

    assert result.decision == ActionDecision.EXECUTE
    assert result.executed is True
    assert result.returncode == 0
    assert result.stdout == "OK"
    assert len(executor.calls) == 1


def test_blocked_action_is_never_executed():
    pipeline = build_pipeline()

    pipeline_result = pipeline.evaluate(
        cpu_percent=95,
        ram_percent=30,
        storage_percent=40,
    )

    executor = FakeExecutor()

    result = SafeExecutionGateway(
        executor=executor,
    ).execute(
        pipeline_result,
        action="HEALTH_CHECK",
        command=["printf", "should-not-run"],
    )

    assert result.decision == ActionDecision.DENY
    assert result.executed is False
    assert result.returncode is None
    assert executor.calls == []
    assert result.reason == "RESOURCE_POLICY_BLOCK"


def test_multiple_resource_failures_still_deny():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=95,
        ram_percent=95,
        storage_percent=95,
    )

    executor = FakeExecutor()

    result = SafeExecutionGateway(
        executor=executor,
    ).execute(
        pipeline_result,
        action="START_PROJECT",
        command=["echo", "blocked"],
    )

    assert result.decision == ActionDecision.DENY
    assert result.executed is False
    assert executor.calls == []


def test_command_must_be_list():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    with pytest.raises(TypeError):
        SafeExecutionGateway(executor=FakeExecutor()).execute(
            pipeline_result,
            action="TEST",
            command="echo hello",
        )


def test_empty_command_rejected():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    with pytest.raises(ValueError):
        SafeExecutionGateway(executor=FakeExecutor()).execute(
            pipeline_result,
            action="TEST",
            command=[],
        )


def test_invalid_command_item_rejected():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    with pytest.raises(TypeError):
        SafeExecutionGateway(executor=FakeExecutor()).execute(
            pipeline_result,
            action="TEST",
            command=["echo", ""],
        )


def test_timeout_is_forwarded():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    executor = FakeExecutor()

    SafeExecutionGateway(
        executor=executor,
    ).execute(
        pipeline_result,
        action="TEST",
        command=["echo", "ok"],
        timeout=7.5,
    )

    assert executor.calls == [
        (["echo", "ok"], 7.5),
    ]


def test_result_is_immutable():
    result = GatewayResult(
        decision=ActionDecision.DENY,
        action="TEST",
        executed=False,
        returncode=None,
        stdout="",
        stderr="",
        reason="RESOURCE_POLICY_BLOCK",
    )

    with pytest.raises(AttributeError):
        result.executed = True


def test_allowed_result_reason():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    result = SafeExecutionGateway(
        executor=FakeExecutor(),
    ).execute(
        pipeline_result,
        action="TEST",
        command=["echo", "ok"],
    )

    assert result.reason == "EXECUTED"


def test_gateway_is_deterministic_for_same_fake_executor():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    gateway = SafeExecutionGateway(
        executor=FakeExecutor(),
    )

    a = gateway.execute(
        pipeline_result,
        action="TEST",
        command=["echo", "ok"],
    )

    b = gateway.execute(
        pipeline_result,
        action="TEST",
        command=["echo", "ok"],
    )

    assert a == b
