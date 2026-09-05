from pathlib import Path

import pytest

from sentinelshield.monitoring_runtime import MonitoringRuntime


def test_runtime_can_be_created(tmp_path: Path):
    runtime = MonitoringRuntime(
        output_path=tmp_path / "status.json",
        interval=1,
    )

    assert runtime.interval == 1


def test_zero_interval_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        MonitoringRuntime(
            output_path=tmp_path / "status.json",
            interval=0,
        )


def test_negative_interval_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        MonitoringRuntime(
            output_path=tmp_path / "status.json",
            interval=-1,
        )


def test_stop_changes_running_state(tmp_path: Path):
    runtime = MonitoringRuntime(
        output_path=tmp_path / "status.json",
        interval=1,
    )

    assert runtime.running is True

    runtime.stop()

    assert runtime.running is False


def test_collect_returns_required_sections(tmp_path: Path):
    runtime = MonitoringRuntime(
        output_path=tmp_path / "status.json",
        interval=1,
    )

    data = runtime.collect()

    assert "timestamp_utc" in data
    assert "cpu" in data
    assert "ram" in data
    assert "storage" in data


def test_cpu_data_is_present(tmp_path: Path):
    runtime = MonitoringRuntime(
        output_path=tmp_path / "status.json",
        interval=1,
    )

    data = runtime.collect()

    assert 0 <= data["cpu"]["percent"] <= 100
    assert data["cpu"]["cpu_count"] >= 1


def test_ram_data_is_present(tmp_path: Path):
    runtime = MonitoringRuntime(
        output_path=tmp_path / "status.json",
        interval=1,
    )

    data = runtime.collect()

    assert 0 <= data["ram"]["percent"] <= 100


def test_storage_data_is_present(tmp_path: Path):
    runtime = MonitoringRuntime(
        output_path=tmp_path / "status.json",
        interval=1,
    )

    data = runtime.collect()

    assert 0 <= data["storage"]["percent"] <= 100


def test_run_once_writes_status_file(tmp_path: Path):
    output = tmp_path / "status.json"

    runtime = MonitoringRuntime(
        output_path=output,
        interval=1,
    )

    data = runtime.run_once()

    assert output.exists()
    assert output.read_text(encoding="utf-8")
    assert data["cpu"]["percent"] >= 0


def test_status_file_contains_json(tmp_path: Path):
    import json

    output = tmp_path / "status.json"

    runtime = MonitoringRuntime(
        output_path=output,
        interval=1,
    )

    runtime.run_once()

    parsed = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert "cpu" in parsed
    assert "ram" in parsed
    assert "storage" in parsed
