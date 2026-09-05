import pytest

from sentinelshield.action_controller import (
    ActionController,
    ActionDecision,
    ActionResult,
)
from sentinelshield.monitoring_policy_pipeline import build_pipeline


def test_allowed_pipeline_returns_execute():
    pipeline = build_pipeline()

    pipeline_result = pipeline.evaluate(
        cpu_percent=20,
        ram_percent=30,
        storage_percent=40,
    )

    result = ActionController().decide(
        pipeline_result,
        action="START_PROJECT",
    )

    assert result.decision == ActionDecision.EXECUTE
    assert result.allowed is True
    assert result.action == "START_PROJECT"
    assert result.reason == "POLICY_ALLOWED"


def test_blocked_pipeline_returns_deny():
    pipeline = build_pipeline()

    pipeline_result = pipeline.evaluate(
        cpu_percent=95,
        ram_percent=30,
        storage_percent=40,
    )

    result = ActionController().decide(
        pipeline_result,
        action="START_PROJECT",
    )

    assert result.decision == ActionDecision.DENY
    assert result.allowed is False
    assert result.reason == "RESOURCE_POLICY_BLOCK"


def test_execute_cannot_happen_when_blocked():
    pipeline = build_pipeline()

    pipeline_result = pipeline.evaluate(
        cpu_percent=95,
        ram_percent=95,
        storage_percent=95,
    )

    result = ActionController().decide(
        pipeline_result,
        action="RUN_COMMAND",
    )

    assert result.decision != ActionDecision.EXECUTE
    assert result.allowed is False


def test_action_name_is_trimmed():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    result = ActionController().decide(
        pipeline_result,
        action="  START_PROJECT  ",
    )

    assert result.action == "START_PROJECT"


def test_empty_action_rejected():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    with pytest.raises(ValueError):
        ActionController().decide(
            pipeline_result,
            action="   ",
        )


def test_non_string_action_rejected():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=10,
        ram_percent=10,
        storage_percent=10,
    )

    with pytest.raises(TypeError):
        ActionController().decide(
            pipeline_result,
            action=123,
        )


def test_invalid_pipeline_result_rejected():
    with pytest.raises(TypeError):
        ActionController().decide(
            object(),
            action="TEST",
        )


def test_require_execute_accepts_execute():
    result = ActionResult(
        decision=ActionDecision.EXECUTE,
        action="TEST",
        allowed=True,
        reason="POLICY_ALLOWED",
    )

    ActionController().require_execute(result)


def test_require_execute_rejects_deny():
    result = ActionResult(
        decision=ActionDecision.DENY,
        action="TEST",
        allowed=False,
        reason="RESOURCE_POLICY_BLOCK",
    )

    with pytest.raises(PermissionError):
        ActionController().require_execute(result)


def test_require_denied_accepts_deny():
    result = ActionResult(
        decision=ActionDecision.DENY,
        action="TEST",
        allowed=False,
        reason="RESOURCE_POLICY_BLOCK",
    )

    ActionController().require_denied(result)


def test_require_denied_rejects_execute():
    result = ActionResult(
        decision=ActionDecision.EXECUTE,
        action="TEST",
        allowed=True,
        reason="POLICY_ALLOWED",
    )

    with pytest.raises(AssertionError):
        ActionController().require_denied(result)


def test_result_is_immutable():
    result = ActionResult(
        decision=ActionDecision.EXECUTE,
        action="TEST",
        allowed=True,
        reason="POLICY_ALLOWED",
    )

    with pytest.raises(AttributeError):
        result.allowed = False


def test_same_input_is_deterministic():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=45,
        ram_percent=55,
        storage_percent=65,
    )

    controller = ActionController()

    a = controller.decide(
        pipeline_result,
        action="CHECK_HEALTH",
    )
    b = controller.decide(
        pipeline_result,
        action="CHECK_HEALTH",
    )

    assert a == b


def test_custom_action_preserved():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=25,
        ram_percent=25,
        storage_percent=25,
    )

    result = ActionController().decide(
        pipeline_result,
        action="RECOVERY_CHECK",
    )

    assert result.action == "RECOVERY_CHECK"
    assert result.decision == ActionDecision.EXECUTE


def test_denial_reason_is_explicit():
    pipeline_result = build_pipeline().evaluate(
        cpu_percent=81,
        ram_percent=10,
        storage_percent=10,
    )

    result = ActionController().decide(
        pipeline_result,
        action="TEST_ACTION",
    )

    assert result.reason == "RESOURCE_POLICY_BLOCK"


def test_monitor_mode_does_not_block_action():
    from sentinelshield.policy import PolicyMode, SentinelPolicy

    pipeline = build_pipeline(
        SentinelPolicy(mode=PolicyMode.MONITOR)
    )

    pipeline_result = pipeline.evaluate(
        cpu_percent=99,
        ram_percent=99,
        storage_percent=99,
    )

    result = ActionController().decide(
        pipeline_result,
        action="MONITOR_ONLY_ACTION",
    )

    assert result.decision == ActionDecision.EXECUTE
    assert result.allowed is True
