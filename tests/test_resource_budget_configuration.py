import pytest

from sentinelshield.resource_budget_configuration import (
    ResourceBudgetConfigurationError,
    ResourceBudgetPolicy,
    configure_resource_budget,
    require_valid_resource_budget,
    validate_resource_budget_policy,
)


def test_default_resource_budget_is_valid():
    result = configure_resource_budget()

    assert result.valid is True
    assert result.cpu_percent == 100.0
    assert result.memory_mb == 2048.0
    assert result.disk_mb == 4096.0
    assert result.process_limit == 32


def test_custom_resource_budget_is_valid():
    result = configure_resource_budget(
        cpu_percent=50,
        memory_mb=1024,
        disk_mb=2048,
        process_limit=16,
    )

    assert result.valid is True
    assert result.cpu_percent == 50.0
    assert result.memory_mb == 1024.0
    assert result.disk_mb == 2048.0
    assert result.process_limit == 16


@pytest.mark.parametrize(
    "value",
    [0, -1, -0.1],
)
def test_invalid_cpu_values_are_rejected(value):
    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(cpu_percent=value)


@pytest.mark.parametrize(
    "value",
    [101, 100.1],
)
def test_cpu_above_100_is_rejected(value):
    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(cpu_percent=value)


@pytest.mark.parametrize(
    "field",
    ["memory_mb", "disk_mb"],
)
def test_non_positive_memory_or_disk_is_rejected(field):
    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(**{field: 0})

    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(**{field: -1})


@pytest.mark.parametrize(
    "value",
    [0, -1, 1.5, "16", True, False],
)
def test_invalid_process_limit_is_rejected(value):
    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(process_limit=value)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_non_finite_cpu_is_rejected(value):
    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(cpu_percent=value)


@pytest.mark.parametrize(
    "field",
    ["memory_mb", "disk_mb"],
)
def test_non_finite_memory_or_disk_is_rejected(field):
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ResourceBudgetConfigurationError):
            configure_resource_budget(**{field: value})


def test_memory_above_policy_limit_is_rejected():
    policy = ResourceBudgetPolicy(
        max_memory_mb=1024,
    )

    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(
            memory_mb=1025,
            policy=policy,
        )


def test_disk_above_policy_limit_is_rejected():
    policy = ResourceBudgetPolicy(
        max_disk_mb=2048,
    )

    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(
            disk_mb=2049,
            policy=policy,
        )


def test_process_limit_above_policy_limit_is_rejected():
    policy = ResourceBudgetPolicy(
        max_process_limit=10,
    )

    with pytest.raises(ResourceBudgetConfigurationError):
        configure_resource_budget(
            process_limit=11,
            policy=policy,
        )


def test_invalid_policy_cpu_limit_is_rejected():
    policy = ResourceBudgetPolicy(
        max_cpu_percent=101,
    )

    with pytest.raises(ResourceBudgetConfigurationError):
        validate_resource_budget_policy(policy)


def test_policy_cpu_cannot_exceed_maximum():
    policy = ResourceBudgetPolicy(
        cpu_percent=90,
        max_cpu_percent=80,
    )

    with pytest.raises(ResourceBudgetConfigurationError):
        validate_resource_budget_policy(policy)


def test_boolean_policy_values_are_rejected():
    policy = ResourceBudgetPolicy(
        cpu_percent=True,
    )

    with pytest.raises(ResourceBudgetConfigurationError):
        validate_resource_budget_policy(policy)


def test_none_uses_policy_defaults():
    policy = ResourceBudgetPolicy(
        cpu_percent=50,
        memory_mb=512,
        disk_mb=1024,
        process_limit=8,
    )

    result = configure_resource_budget(
        cpu_percent=None,
        memory_mb=None,
        disk_mb=None,
        process_limit=None,
        policy=policy,
    )

    assert result.cpu_percent == 50.0
    assert result.memory_mb == 512.0
    assert result.disk_mb == 1024.0
    assert result.process_limit == 8


def test_result_to_dict():
    result = configure_resource_budget(
        cpu_percent=25,
        memory_mb=512,
        disk_mb=1024,
        process_limit=8,
    )

    data = result.to_dict()

    assert data["valid"] is True
    assert data["cpu_percent"] == 25.0
    assert data["memory_mb"] == 512.0
    assert data["disk_mb"] == 1024.0
    assert data["process_limit"] == 8


def test_require_valid_resource_budget():
    result = require_valid_resource_budget(
        cpu_percent=25,
        memory_mb=256,
        disk_mb=512,
        process_limit=4,
    )

    assert result.valid is True
    assert result.process_limit == 4
