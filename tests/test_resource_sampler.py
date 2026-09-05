from types import SimpleNamespace

from sentinelshield.resource_sampler import (
    ResourceSampler,
    ResourceSnapshot,
)


class FakePsutil:
    def cpu_percent(self, interval=0.1):
        assert interval == 0.1
        return 25.5

    def virtual_memory(self):
        return SimpleNamespace(percent=35.5)


def test_real_sampler_returns_snapshot():
    sampler = ResourceSampler(psutil_module=FakePsutil())

    result = sampler.sample()

    assert isinstance(result, ResourceSnapshot)
    assert result.cpu_percent == 25.5
    assert result.ram_percent == 35.5
    assert 0 <= result.storage_percent <= 100


def test_sample_dict():
    sampler = ResourceSampler(psutil_module=FakePsutil())

    result = sampler.sample_dict()

    assert result["cpu_percent"] == 25.5
    assert result["ram_percent"] == 35.5
    assert 0 <= result["storage_percent"] <= 100


def test_snapshot_is_immutable():
    sampler = ResourceSampler(psutil_module=FakePsutil())

    result = sampler.sample()

    try:
        result.cpu_percent = 50
        assert False
    except AttributeError:
        pass


def test_cpu_value_is_float():
    sampler = ResourceSampler(psutil_module=FakePsutil())

    result = sampler.sample()

    assert isinstance(result.cpu_percent, float)


def test_ram_value_is_float():
    sampler = ResourceSampler(psutil_module=FakePsutil())

    result = sampler.sample()

    assert isinstance(result.ram_percent, float)


def test_storage_value_is_float():
    sampler = ResourceSampler(psutil_module=FakePsutil())

    result = sampler.sample()

    assert isinstance(result.storage_percent, float)
