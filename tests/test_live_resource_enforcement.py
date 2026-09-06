from types import SimpleNamespace

from sentinelshield.live_resource_enforcement import (
    LiveResourceDecision,
    LiveResourceEnforcer,
)


class FakeSampler:
    def __init__(
        self,
        cpu=10,
        ram=20,
        storage=30,
    ):
        self.snapshot = SimpleNamespace(
            cpu_percent=cpu,
            ram_percent=ram,
            storage_percent=storage,
        )
        self.calls = 0

    def sample(self):
        self.calls += 1
        return self.snapshot


class FakeEnforcement:
    def __init__(
        self,
        safe=True,
        decision="ALLOW",
        failures=(),
        reason="SAFE",
    ):
        self.safe = safe
        self.decision = decision
        self.failures = failures
        self.reason = reason
        self.calls = []

    def evaluate(
        self,
        cpu_percent,
        ram_percent,
        storage_percent,
    ):
        self.calls.append(
            (
                cpu_percent,
                ram_percent,
                storage_percent,
            )
        )

        return SimpleNamespace(
            safe=self.safe,
            decision=SimpleNamespace(
                value=self.decision,
            ),
            failures=self.failures,
            reason=self.reason,
        )


def test_live_resource_decision_is_created():
    sampler = FakeSampler()
    enforcement = FakeEnforcement()

    result = LiveResourceEnforcer(
        sampler,
        enforcement,
    ).check()

    assert isinstance(
        result,
        LiveResourceDecision,
    )

    assert result.allowed is True
    assert result.blocked is False
    assert result.decision == "ALLOW"


def test_sampler_is_called_once():
    sampler = FakeSampler()
    enforcement = FakeEnforcement()

    LiveResourceEnforcer(
        sampler,
        enforcement,
    ).check()

    assert sampler.calls == 1


def test_values_are_forwarded_to_enforcement():
    sampler = FakeSampler(
        cpu=25,
        ram=35,
        storage=45,
    )

    enforcement = FakeEnforcement()

    LiveResourceEnforcer(
        sampler,
        enforcement,
    ).check()

    assert enforcement.calls == [
        (25, 35, 45)
    ]


def test_unsafe_result_is_blocked():
    sampler = FakeSampler(
        cpu=95,
        ram=95,
        storage=95,
    )

    enforcement = FakeEnforcement(
        safe=False,
        decision="BLOCK",
        failures=("CPU",),
        reason="RESOURCE_LIMIT",
    )

    result = LiveResourceEnforcer(
        sampler,
        enforcement,
    ).check()

    assert result.allowed is False
    assert result.blocked is True
    assert result.decision == "BLOCK"
    assert result.failures == ("CPU",)
    assert result.reason == "RESOURCE_LIMIT"


def test_failure_list_is_immutable_tuple():
    sampler = FakeSampler()

    enforcement = FakeEnforcement(
        failures=["CPU", "RAM"],
    )

    result = LiveResourceEnforcer(
        sampler,
        enforcement,
    ).check()

    assert isinstance(
        result.failures,
        tuple,
    )

    assert result.failures == (
        "CPU",
        "RAM",
    )


def test_resource_values_are_preserved():
    sampler = FakeSampler(
        cpu=11.5,
        ram=22.5,
        storage=33.5,
    )

    enforcement = FakeEnforcement()

    result = LiveResourceEnforcer(
        sampler,
        enforcement,
    ).check()

    assert result.cpu_percent == 11.5
    assert result.ram_percent == 22.5
    assert result.storage_percent == 33.5


def test_live_check_does_not_require_project_path():
    sampler = FakeSampler()
    enforcement = FakeEnforcement()

    result = LiveResourceEnforcer(
        sampler,
        enforcement,
    ).check()

    assert result.allowed is True


def test_multiple_checks_are_supported():
    sampler = FakeSampler()
    enforcement = FakeEnforcement()

    checker = LiveResourceEnforcer(
        sampler,
        enforcement,
    )

    first = checker.check()
    second = checker.check()

    assert first.allowed is True
    assert second.allowed is True
    assert sampler.calls == 2
    assert len(enforcement.calls) == 2
