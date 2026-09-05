import pytest

from sentinelshield.recovery_controller import (
    RecoveryController,
    RecoveryError,
    RecoveryPlan,
    RecoveryState,
    RecoveryStatus,
)


def test_initial_status_is_idle():
    controller = RecoveryController()

    assert controller.status == RecoveryStatus.IDLE


def test_initial_state_is_clean():
    controller = RecoveryController()

    state = controller.state()

    assert isinstance(state, RecoveryState)
    assert state.status == RecoveryStatus.IDLE
    assert state.reason == ""
    assert state.actions_completed == 0
    assert state.total_actions == 0


def test_recovery_can_be_required():
    controller = RecoveryController()

    plan = controller.require_recovery(
        "command failed",
        ["inspect", "restore"],
    )

    assert isinstance(plan, RecoveryPlan)
    assert controller.status == RecoveryStatus.REQUIRED
    assert plan.reason == "command failed"
    assert plan.actions == ("inspect", "restore")


def test_required_state_resets_action_counter():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one"],
    )

    state = controller.state()

    assert state.actions_completed == 0
    assert state.total_actions == 1


def test_start_moves_required_to_running():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["restore"],
    )

    state = controller.start()

    assert state.status == RecoveryStatus.RUNNING


def test_start_without_required_recovery_fails():
    controller = RecoveryController()

    with pytest.raises(RecoveryError):
        controller.start()


def test_complete_action_increments_counter():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one", "two"],
    )

    controller.start()

    state = controller.complete_action()

    assert state.actions_completed == 1
    assert state.total_actions == 2


def test_all_actions_can_be_completed():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one", "two"],
    )

    controller.start()
    controller.complete_action()
    state = controller.complete_action()

    assert state.actions_completed == 2
    assert state.total_actions == 2


def test_cannot_complete_action_before_start():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one"],
    )

    with pytest.raises(RecoveryError):
        controller.complete_action()


def test_cannot_complete_more_actions_than_plan():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one"],
    )

    controller.start()
    controller.complete_action()

    with pytest.raises(RecoveryError):
        controller.complete_action()


def test_recovery_succeeds_after_all_actions():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one", "two"],
    )

    controller.start()
    controller.complete_action()
    controller.complete_action()

    state = controller.succeed()

    assert state.status == RecoveryStatus.SUCCESS


def test_recovery_cannot_succeed_early():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one", "two"],
    )

    controller.start()
    controller.complete_action()

    with pytest.raises(RecoveryError):
        controller.succeed()


def test_recovery_cannot_succeed_before_start():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["one"],
    )

    with pytest.raises(RecoveryError):
        controller.succeed()


def test_recovery_failure_changes_status():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["restore"],
    )

    controller.start()

    state = controller.fail(
        "restore operation failed"
    )

    assert state.status == RecoveryStatus.FAILED
    assert state.reason == "restore operation failed"


def test_failure_without_custom_reason_preserves_reason():
    controller = RecoveryController()

    controller.require_recovery(
        "original failure",
        ["restore"],
    )

    controller.start()
    state = controller.fail()

    assert state.status == RecoveryStatus.FAILED
    assert state.reason == "original failure"


def test_failed_recovery_cannot_complete_action():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["restore"],
    )

    controller.start()
    controller.fail()

    with pytest.raises(RecoveryError):
        controller.complete_action()


def test_failed_recovery_cannot_succeed():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["restore"],
    )

    controller.start()
    controller.fail()

    with pytest.raises(RecoveryError):
        controller.succeed()


def test_reset_returns_to_idle():
    controller = RecoveryController()

    controller.require_recovery(
        "failure",
        ["restore"],
    )

    controller.start()
    controller.reset()

    state = controller.state()

    assert state.status == RecoveryStatus.IDLE
    assert state.reason == ""
    assert state.actions_completed == 0
    assert state.total_actions == 0


def test_empty_reason_is_rejected():
    controller = RecoveryController()

    with pytest.raises(ValueError):
        controller.require_recovery(
            "",
            ["restore"],
        )


def test_whitespace_reason_is_rejected():
    controller = RecoveryController()

    with pytest.raises(ValueError):
        controller.require_recovery(
            "   ",
            ["restore"],
        )


def test_invalid_reason_type_is_rejected():
    controller = RecoveryController()

    with pytest.raises(TypeError):
        controller.require_recovery(
            123,
            ["restore"],
        )


def test_invalid_actions_type_is_rejected():
    controller = RecoveryController()

    with pytest.raises(TypeError):
        controller.require_recovery(
            "failure",
            "restore",
        )


def test_invalid_action_type_is_rejected():
    controller = RecoveryController()

    with pytest.raises(TypeError):
        controller.require_recovery(
            "failure",
            ["restore", 123],
        )


def test_empty_action_is_rejected():
    controller = RecoveryController()

    with pytest.raises(ValueError):
        controller.require_recovery(
            "failure",
            ["restore", ""],
        )


def test_empty_action_list_is_allowed():
    controller = RecoveryController()

    plan = controller.require_recovery(
        "nothing to restore",
        [],
    )

    assert plan.actions == ()
    assert controller.state().total_actions == 0


def test_recovery_plan_is_immutable():
    controller = RecoveryController()

    plan = controller.require_recovery(
        "failure",
        ["restore"],
    )

    assert isinstance(plan.actions, tuple)

    with pytest.raises(AttributeError):
        plan.reason = "changed"


def test_recovery_state_is_immutable():
    controller = RecoveryController()

    state = controller.state()

    with pytest.raises(AttributeError):
        state.status = RecoveryStatus.RUNNING


def test_new_recovery_plan_replaces_previous_plan():
    controller = RecoveryController()

    controller.require_recovery(
        "first failure",
        ["one", "two"],
    )

    controller.require_recovery(
        "second failure",
        ["restore"],
    )

    state = controller.state()

    assert state.reason == "second failure"
    assert state.total_actions == 1
    assert state.actions_completed == 0
