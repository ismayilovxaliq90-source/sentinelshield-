import pytest

from sentinelshield.policy import PolicyEngine, PolicyMode, SentinelPolicy


def test_default_policy():
    p = SentinelPolicy()
    assert p.mode == PolicyMode.ENFORCE
    assert p.cpu_limit_percent == 80.0
    assert p.ram_limit_percent == 80.0
    assert p.storage_limit_percent == 90.0


def test_monitor_mode():
    assert SentinelPolicy(mode=PolicyMode.MONITOR).mode == PolicyMode.MONITOR


def test_resource_limits():
    p = SentinelPolicy(cpu_limit_percent=70, ram_limit_percent=75, storage_limit_percent=85)
    assert p.resource_limits == {
        "cpu": 70.0,
        "ram": 75.0,
        "storage": 85.0,
    }


def test_custom_values():
    p = SentinelPolicy(
        check_interval_seconds=2,
        command_timeout_seconds=15,
        max_processes=50,
        max_log_size_mb=25,
    )
    assert p.check_interval_seconds == 2
    assert p.command_timeout_seconds == 15
    assert p.max_processes == 50
    assert p.max_log_size_mb == 25


def test_flags():
    p = SentinelPolicy(
        recovery_enabled=False,
        emergency_stop_enabled=False,
    )
    assert p.recovery_enabled is False
    assert p.emergency_stop_enabled is False


@pytest.mark.parametrize(
    "field",
    ["cpu_limit_percent", "ram_limit_percent", "storage_limit_percent"],
)
def test_percent_zero_rejected(field):
    with pytest.raises(ValueError):
        SentinelPolicy(**{field: 0})


@pytest.mark.parametrize(
    "field",
    ["cpu_limit_percent", "ram_limit_percent", "storage_limit_percent"],
)
def test_percent_above_100_rejected(field):
    with pytest.raises(ValueError):
        SentinelPolicy(**{field: 101})


def test_interval_zero_rejected():
    with pytest.raises(ValueError):
        SentinelPolicy(check_interval_seconds=0)


def test_timeout_zero_rejected():
    with pytest.raises(ValueError):
        SentinelPolicy(command_timeout_seconds=0)


def test_process_zero_rejected():
    with pytest.raises(ValueError):
        SentinelPolicy(max_processes=0)


def test_log_zero_rejected():
    with pytest.raises(ValueError):
        SentinelPolicy(max_log_size_mb=0)


def test_mode_type_rejected():
    with pytest.raises(TypeError):
        SentinelPolicy(mode="ENFORCE")


def test_policy_is_immutable():
    p = SentinelPolicy()
    with pytest.raises(AttributeError):
        p.cpu_limit_percent = 50


def test_as_dict():
    p = SentinelPolicy()
    d = p.as_dict()
    assert d["mode"] == "ENFORCE"
    assert d["cpu_limit_percent"] == 80.0


def test_engine_default():
    e = PolicyEngine()
    assert e.policy.cpu_limit_percent == 80.0


def test_engine_replace():
    e = PolicyEngine()
    p = SentinelPolicy(cpu_limit_percent=60)
    assert e.replace(p) is p
    assert e.policy.cpu_limit_percent == 60


def test_engine_limits():
    e = PolicyEngine(
        SentinelPolicy(
            cpu_limit_percent=60,
            ram_limit_percent=70,
            storage_limit_percent=80,
        )
    )
    assert e.limits() == {
        "cpu": 60.0,
        "ram": 70.0,
        "storage": 80.0,
    }


def test_engine_rejects_invalid():
    e = PolicyEngine()
    with pytest.raises(TypeError):
        e.replace(object())
