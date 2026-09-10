import math

import pytest

from sentinelshield.timeout_configuration import (
    TimeoutConfigurationError,
    TimeoutPolicy,
    configure_timeout,
    require_valid_timeout,
    validate_timeout_policy,
)


def test_default_timeout_is_valid():
    result = configure_timeout()

    assert result.valid is True
    assert result.timeout == 60.0
    assert result.reason == "VALID_TIMEOUT"


def test_custom_timeout_within_bounds():
    policy = TimeoutPolicy(
        default_timeout=30.0,
        minimum_timeout=1.0,
        maximum_timeout=120.0,
    )

    result = configure_timeout(45.0, policy)

    assert result.valid is True
    assert result.timeout == 45.0


def test_minimum_boundary_is_allowed():
    policy = TimeoutPolicy(
        minimum_timeout=5.0,
        maximum_timeout=100.0,
    )

    result = configure_timeout(5.0, policy)

    assert result.timeout == 5.0


def test_maximum_boundary_is_allowed():
    policy = TimeoutPolicy(
        minimum_timeout=5.0,
        maximum_timeout=100.0,
    )

    result = configure_timeout(100.0, policy)

    assert result.timeout == 100.0


@pytest.mark.parametrize(
    "value",
    [0, -1, -0.1],
)
def test_non_positive_timeout_is_rejected(value):
    with pytest.raises(TimeoutConfigurationError):
        configure_timeout(value)


def test_timeout_above_maximum_is_rejected():
    policy = TimeoutPolicy(
        minimum_timeout=1.0,
        maximum_timeout=10.0,
    )

    with pytest.raises(TimeoutConfigurationError):
        configure_timeout(10.01, policy)


def test_timeout_below_minimum_is_rejected():
    policy = TimeoutPolicy(
        minimum_timeout=10.0,
        maximum_timeout=100.0,
    )

    with pytest.raises(TimeoutConfigurationError):
        configure_timeout(9.99, policy)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_non_finite_timeout_is_rejected(value):
    with pytest.raises(TimeoutConfigurationError):
        configure_timeout(value)


@pytest.mark.parametrize(
    "value",
    [None, True, False, "60", object()],
)
def test_invalid_timeout_types_are_rejected(value):
    if value is None:
        result = configure_timeout(None)
        assert result.valid is True
    else:
        with pytest.raises(TimeoutConfigurationError):
            configure_timeout(value)


def test_invalid_policy_bounds_are_rejected():
    policy = TimeoutPolicy(
        default_timeout=5.0,
        minimum_timeout=10.0,
        maximum_timeout=1.0,
    )

    with pytest.raises(TimeoutConfigurationError):
        validate_timeout_policy(policy)


def test_default_must_be_inside_bounds():
    policy = TimeoutPolicy(
        default_timeout=1000.0,
        minimum_timeout=1.0,
        maximum_timeout=100.0,
    )

    with pytest.raises(TimeoutConfigurationError):
        validate_timeout_policy(policy)


def test_zero_minimum_is_rejected():
    policy = TimeoutPolicy(
        default_timeout=10.0,
        minimum_timeout=0.0,
        maximum_timeout=100.0,
    )

    with pytest.raises(TimeoutConfigurationError):
        validate_timeout_policy(policy)


def test_boolean_policy_values_are_rejected():
    policy = TimeoutPolicy(
        default_timeout=True,
        minimum_timeout=1.0,
        maximum_timeout=100.0,
    )

    with pytest.raises(TimeoutConfigurationError):
        validate_timeout_policy(policy)


def test_require_valid_timeout_returns_float():
    value = require_valid_timeout(15)

    assert isinstance(value, float)
    assert value == 15.0


def test_result_to_dict():
    result = configure_timeout(25)

    data = result.to_dict()

    assert data["valid"] is True
    assert data["timeout"] == 25.0
    assert data["minimum_timeout"] == 0.1
    assert data["maximum_timeout"] == 600.0


def test_policy_validation_does_not_execute_any_operation():
    result = validate_timeout_policy()

    assert result.valid is True
    assert math.isfinite(result.timeout)
