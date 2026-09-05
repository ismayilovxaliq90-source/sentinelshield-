from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinelshield.audit_engine import AuditEngine
from sentinelshield.live_security_loop import LiveSecurityLoop


class FakeSampler:
    def sample(self):
        return SimpleNamespace(
            cpu_percent=20.0,
            ram_percent=30.0,
            storage_percent=40.0,
        )


class BlockingSampler:
    def sample(self):
        return SimpleNamespace(
            cpu_percent=99.0,
            ram_percent=99.0,
            storage_percent=99.0,
        )


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def run(self, command, timeout=30.0):
        self.calls.append((command, timeout))

        return SimpleNamespace(
            returncode=0,
            stdout="EXECUTED",
            stderr="",
        )


def make_loop(tmp_path, sampler):
    from sentinelshield.live_monitor import LiveMonitor
    from sentinelshield.safe_execution_gateway import SafeExecutionGateway

    audit = AuditEngine(tmp_path / "audit.jsonl")
    executor = FakeExecutor()

    live_monitor = LiveMonitor(
        sampler=sampler,
    )

    gateway = SafeExecutionGateway(
        executor=executor,
        audit=audit,
    )

    loop = LiveSecurityLoop(
        live_monitor=live_monitor,
        gateway=gateway,
        audit=audit,
    )

    return loop, executor, audit


def test_safe_resource_path_executes(tmp_path):
    loop, executor, audit = make_loop(
        tmp_path,
        FakeSampler(),
    )

    result = loop.evaluate_action(
        action="HEALTH_CHECK",
        command=["echo", "safe"],
    )

    assert result.executed is True
    assert result.allowed is True
    assert result.returncode == 0

    assert len(executor.calls) == 1

    events = audit.read_all()

    assert len(events) == 1
    assert events[0]["event"] == "ACTION_EXECUTED"
    assert events[0]["executed"] is True


def test_blocked_resource_path_never_executes(tmp_path):
    loop, executor, audit = make_loop(
        tmp_path,
        BlockingSampler(),
    )

    result = loop.evaluate_action(
        action="START_PROJECT",
        command=["echo", "blocked"],
    )

    assert result.executed is False
    assert result.allowed is False
    assert result.decision.value == "DENY"

    assert executor.calls == []

    events = audit.read_all()

    assert len(events) == 1
    assert events[0]["event"] == "ACTION_DENIED"
    assert events[0]["executed"] is False


def test_multiple_safe_cycles(tmp_path):
    loop, executor, audit = make_loop(
        tmp_path,
        FakeSampler(),
    )

    results = []

    completed = loop.run(
        action="HEALTH_CHECK",
        command=["echo", "ok"],
        max_cycles=3,
        on_result=results.append,
    )

    assert completed == 3
    assert len(results) == 3
    assert len(executor.calls) == 3

    events = audit.read_all()

    assert len(events) == 3
    assert all(
        event["event"] == "ACTION_EXECUTED"
        for event in events
    )


def test_multiple_blocked_cycles(tmp_path):
    loop, executor, audit = make_loop(
        tmp_path,
        BlockingSampler(),
    )

    results = []

    completed = loop.run(
        action="START_PROJECT",
        command=["echo", "blocked"],
        max_cycles=3,
        on_result=results.append,
    )

    assert completed == 3
    assert len(results) == 3
    assert executor.calls == []

    events = audit.read_all()

    assert len(events) == 3
    assert all(
        event["event"] == "ACTION_DENIED"
        for event in events
    )


def test_empty_action_rejected(tmp_path):
    loop, _, _ = make_loop(
        tmp_path,
        FakeSampler(),
    )

    with pytest.raises(ValueError):
        loop.evaluate_action(
            action="",
            command=["echo", "x"],
        )


def test_empty_command_rejected(tmp_path):
    loop, _, _ = make_loop(
        tmp_path,
        FakeSampler(),
    )

    with pytest.raises(ValueError):
        loop.evaluate_action(
            action="TEST",
            command=[],
        )


def test_audit_property(tmp_path):
    loop, _, audit = make_loop(
        tmp_path,
        FakeSampler(),
    )

    assert loop.audit is audit


def test_gateway_property(tmp_path):
    loop, _, audit = make_loop(
        tmp_path,
        FakeSampler(),
    )

    assert loop.gateway is not None


def test_live_monitor_property(tmp_path):
    loop, _, _ = make_loop(
        tmp_path,
        FakeSampler(),
    )

    assert loop.live_monitor is not None


def test_audit_persists_decision(tmp_path):
    loop, _, audit = make_loop(
        tmp_path,
        BlockingSampler(),
    )

    loop.evaluate_action(
        action="TEST_BLOCK",
        command=["echo", "no"],
    )

    audit_path = Path(tmp_path / "audit.jsonl")

    assert audit_path.exists()
    assert audit_path.read_text(encoding="utf-8").strip()


def test_safe_and_blocked_are_distinct(tmp_path):
    safe_loop, safe_executor, safe_audit = make_loop(
        tmp_path / "safe",
        FakeSampler(),
    )

    blocked_loop, blocked_executor, blocked_audit = make_loop(
        tmp_path / "blocked",
        BlockingSampler(),
    )

    safe = safe_loop.evaluate_action(
        action="SAFE",
        command=["echo", "safe"],
    )

    blocked = blocked_loop.evaluate_action(
        action="BLOCKED",
        command=["echo", "blocked"],
    )

    assert safe.executed is True
    assert blocked.executed is False

    assert len(safe_executor.calls) == 1
    assert blocked_executor.calls == []

    assert safe_audit.read_all()[0]["decision"] == "EXECUTE"
    assert blocked_audit.read_all()[0]["decision"] == "DENY"
