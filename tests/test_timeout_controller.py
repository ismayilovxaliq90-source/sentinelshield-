import time

import pytest

from sentinelshield.timeout_controller import (
    TimeoutController,
    TimeoutControllerError,
    TimeoutState,
)


def test_zero_timeout_is_rejected():
    with pytest.raises(ValueError):
        TimeoutController(0)


def test_negative_timeout_is_rejected():
    with pytest.raises(ValueError):
        TimeoutController(-1)


def test_controller_must_be_started_before_elapsed():
    controller = TimeoutController(1)

    with pytest.raises(TimeoutControllerError):
        controller.elapsed()


def test_controller_must_be_started_before_expired():
    controller = TimeoutController(1)

    with pytest.raises(TimeoutControllerError):
        controller.expired()


def test_start_initializes_controller():
    controller = TimeoutController(1)

    controller.start()

    assert controller.elapsed() >= 0
    assert controller.expired() is False


def test_remaining_time_is_non_negative():
    controller = TimeoutController(1)

    controller.start()

    assert controller.remaining() >= 0


def test_state_returns_timeout_state():
    controller = TimeoutController(1)

    controller.start()

    state = controller.state()

    assert isinstance(state, TimeoutState)
    assert state.timeout == 1
    assert state.elapsed >= 0
    assert state.expired is False


def test_timeout_expires():
    controller = TimeoutController(0.02)

    controller.start()

    time.sleep(0.05)

    assert controller.expired() is True


def test_remaining_becomes_zero_after_timeout():
    controller = TimeoutController(0.02)

    controller.start()

    time.sleep(0.05)

    assert controller.remaining() == 0.0


def test_check_passes_before_timeout():
    controller = TimeoutController(1)

    controller.start()

    state = controller.check()

    assert state.expired is False


def test_check_raises_after_timeout():
    controller = TimeoutController(0.02)

    controller.start()

    time.sleep(0.05)

    with pytest.raises(TimeoutControllerError):
        controller.check()


def test_elapsed_time_does_not_become_negative():
    controller = TimeoutController(1)

    controller.start()

    assert controller.elapsed() >= 0


def test_state_reports_expiration():
    controller = TimeoutController(0.02)

    controller.start()

    time.sleep(0.05)

    state = controller.state()

    assert state.expired is True
    assert state.elapsed >= state.timeout
