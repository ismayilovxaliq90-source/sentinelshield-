import pytest

from sentinelshield.resource_budget_configuration import (
    ResourceBudget,
    ResourceBudgetError,
    ResourceBudgetPolicy,
    configure_resource_budget,
    require_valid_resource_budget,
    validate_resource_budget_policy,
)


def test_default_resource_budget_is_valid():
    result = configure_resource_budget()

    assert result.valid is True
    assert isinstance(result.budget, ResourceBudget)
    assert result.budget.cpu_seconds == 300
    assert result.budget.memory_mb == 1024
    assert result.budget.disk_mb == 2048
    assert result.budget.processes == 32


def test_custom_budget_within_bounds():
    policy = ResourceBudgetPolicy(
        minimum_cpu_seconds=1,
        maximum_cpu_seconds=600,
        minimum_memory_mb=16,
        maximum_memory_mb=4096,
        minimum_disk_mb=16,
        maximum_disk_mb=8192,
        minimum_processes=1,
        maximum_processes=64,
    )

    result = configure_resource_budget(
        cpu_seconds=120,
        memory_mb=512,
        disk_mb=1024,
        processes=8,
        policy=policy,
    )

    assert result.valid is True
    assert result.budget.cpu_seconds == 120
    assert result.budget.memory_mb == 512
    assert result.budget.disk_mb == 1024
    assert result.budget.processes == 8


@pytest.mark.parametrize(
    "field",
    ["cpu_seconds", "memory_mb", "disk_mb", "processes"],
)
def test_zero_is_rejected(field):
    kwargs = {field: 0}

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(**kwargs)


@pytest.mark.parametrize(
    "field",
    ["cpu_seconds", "memory_mb", "disk_mb", "processes"],
)
def test_negative_value_is_rejected(field):
    kwargs = {field: -1}

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(**kwargs)


@pytest.mark.parametrize(
    "field",
    ["cpu_seconds", "memory_mb", "disk_mb", "processes"],
)
def test_boolean_value_is_rejected(field):
    kwargs = {field: True}

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(**kwargs)


@pytest.mark.parametrize(
    "field",
    ["cpu_seconds", "memory_mb", "disk_mb", "processes"],
)
def test_float_value_is_rejected(field):
    kwargs = {field: 10.5}

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(**kwargs)


@pytest.mark.parametrize(
    "field",
    ["cpu_seconds", "memory_mb", "disk_mb", "processes"],
)
def test_string_value_is_rejected(field):
    kwargs = {field: "10"}

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(**kwargs)


@pytest.mark.parametrize(
    "field",
    ["cpu_seconds", "memory_mb", "disk_mb", "processes"],
)
def test_none_explicitly_uses_default(field):
    kwargs = {field: None}

    result = configure_resource_budget(**kwargs)

    assert result.valid is True


def test_cpu_maximum_is_enforced():
    policy = ResourceBudgetPolicy(
        maximum_cpu_seconds=100,
    )

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(
            cpu_seconds=101,
            policy=policy,
        )


def test_memory_maximum_is_enforced():
    policy = ResourceBudgetPolicy(
        maximum_memory_mb=1024,
    )

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(
            memory_mb=1025,
            policy=policy,
        )


def test_disk_maximum_is_enforced():
    policy = ResourceBudgetPolicy(
        maximum_disk_mb=2048,
    )

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(
            disk_mb=2049,
            policy=policy,
        )


def test_process_maximum_is_enforced():
    policy = ResourceBudgetPolicy(
        maximum_processes=16,
    )

    with pytest.raises(ResourceBudgetError):
        configure_resource_budget(
            processes=17,
            policy=policy,
        )


def test_minimum_boundary_is_allowed():
    policy = ResourceBudgetPolicy(
        minimum_cpu_seconds=5,
        maximum_cpu_seconds=100,
        minimum_memory_mb=32,
        maximum_memory_mb=1000,
        minimum_disk_mb=32,
        maximum_disk_mb=2000,
        minimum_processes=2,
        maximum_processes=20,
    )

    result = configure_resource_budget(
        cpu_seconds=5,
        memory_mb=32,
        disk_mb=32,
        processes=2,
        policy=policy,
    )

    assert result.valid is True


def test_maximum_boundary_is_allowed():
    policy = ResourceBudgetPolicy(
        maximum_cpu_seconds=100,
        maximum_memory_mb=1000,
        maximum_disk_mb=2000,
        maximum_processes=20,
    )

    result = configure_resource_budget(
        cpu_seconds=100,
        memory_mb=1000,
        disk_mb=2000,
        processes=20,
        policy=policy,
    )

    assert result.valid is True


def test_invalid_policy_range_is_rejected():
    policy = ResourceBudgetPolicy(
        minimum_cpu_seconds=100,
        maximum_cpu_seconds=10,
    )

    with pytest.raises(ResourceBudgetError):
        validate_resource_budget_policy(policy)


def test_default_outside_policy_is_rejected():
    policy = ResourceBudgetPolicy(
        default_memory_mb=4096,
        minimum_memory_mb=16,
        maximum_memory_mb=1024,
    )

    with pytest.raises(ResourceBudgetError):
        validate_resource_budget_policy(policy)


def test_invalid_policy_type_is_rejected():
    with pytest.raises(ResourceBudgetError):
        validate_resource_budget_policy(object())


def test_require_returns_resource_budget():
    budget = require_valid_resource_budget(
        cpu_seconds=60,
        memory_mb=256,
        disk_mb=512,
        processes=4,
    )

    assert isinstance(budget, ResourceBudget)
    assert budget.cpu_seconds == 60
    assert budget.memory_mb == 256
    assert budget.disk_mb == 512
    assert budget.processes == 4


def test_to_dict_contains_all_resource_limits():
    result = configure_resource_budget()

    data = result.to_dict()

    assert data["valid"] is True
    assert data["reason"] == "VALID_RESOURCE_BUDGET"

    budget = data["budget"]

    assert budget["cpu_seconds"] == 300
    assert budget["memory_mb"] == 1024
    assert budget["disk_mb"] == 2048
    assert budget["processes"] == 32


def test_configuration_does_not_modify_real_resources():
    result = configure_resource_budget(
        cpu_seconds=10,
        memory_mb=128,
        disk_mb=256,
        processes=2,
    )

    assert result.valid is True
