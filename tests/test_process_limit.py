import pytest

from sentinelshield.process_limit import (
    ProcessLimit,
    ProcessLimitError,
    ProcessLimitState,
)


def test_default_limit_is_positive():
    controller = ProcessLimit()

    assert controller.limit > 0


def test_custom_limit_is_accepted():
    controller = ProcessLimit(limit=8)

    assert controller.limit == 8


def test_zero_limit_is_rejected():
    with pytest.raises(ValueError):
        ProcessLimit(limit=0)


def test_negative_limit_is_rejected():
    with pytest.raises(ValueError):
        ProcessLimit(limit=-1)


def test_non_integer_limit_is_rejected():
    with pytest.raises(TypeError):
        ProcessLimit(limit="8")


def test_boolean_limit_is_rejected():
    with pytest.raises(TypeError):
        ProcessLimit(limit=True)


def test_zero_active_processes_are_allowed():
    controller = ProcessLimit(limit=4)

    state = controller.check(0)

    assert isinstance(state, ProcessLimitState)
    assert state.active == 0
    assert state.limit == 4
    assert state.allowed is True


def test_process_count_at_limit_is_allowed():
    controller = ProcessLimit(limit=4)

    state = controller.check(4)

    assert state.allowed is True


def test_process_count_above_limit_is_blocked():
    controller = ProcessLimit(limit=4)

    state = controller.check(5)

    assert state.allowed is False


def test_negative_active_count_is_rejected():
    controller = ProcessLimit(limit=4)

    with pytest.raises(ValueError):
        controller.check(-1)


def test_non_integer_active_count_is_rejected():
    controller = ProcessLimit(limit=4)

    with pytest.raises(TypeError):
        controller.check("4")


def test_boolean_active_count_is_rejected():
    controller = ProcessLimit(limit=4)

    with pytest.raises(TypeError):
        controller.check(True)


def test_is_allowed_returns_true_within_limit():
    controller = ProcessLimit(limit=4)

    assert controller.is_allowed(3) is True


def test_is_allowed_returns_false_above_limit():
    controller = ProcessLimit(limit=4)

    assert controller.is_allowed(5) is False


def test_require_allowed_returns_state_when_safe():
    controller = ProcessLimit(limit=4)

    state = controller.require_allowed(4)

    assert state.allowed is True
    assert state.active == 4
    assert state.limit == 4


def test_require_allowed_raises_when_limit_exceeded():
    controller = ProcessLimit(limit=4)

    with pytest.raises(ProcessLimitError):
        controller.require_allowed(5)


def test_process_limit_does_not_modify_limit():
    controller = ProcessLimit(limit=4)

    controller.check(3)

    assert controller.limit == 4


def test_process_limit_evaluation_is_deterministic():
    controller = ProcessLimit(limit=4)

    first = controller.check(3)
    second = controller.check(3)

    assert first == second


def test_exact_boundary_is_consistently_allowed():
    controller = ProcessLimit(limit=10)

    assert controller.is_allowed(10) is True
    assert controller.is_allowed(11) is False
