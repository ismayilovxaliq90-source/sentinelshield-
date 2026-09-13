from pathlib import Path

from sentinelshield.baseline_snapshot import BaselineSnapshot


def test_baseline_snapshot_contains_required_fields(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    sample = workspace / "sample.txt"
    sample.write_text("sentinelshield", encoding="utf-8")

    snapshot = BaselineSnapshot(workspace).capture()

    assert snapshot["schema_version"] == 1
    assert "timestamp_utc" in snapshot
    assert "python" in snapshot
    assert "platform" in snapshot
    assert snapshot["workspace"] == str(workspace.resolve())
    assert len(snapshot["files"]) == 1

    entry = snapshot["files"][0]

    assert entry["path"] == "sample.txt"
    assert entry["size"] == len("sentinelshield")
    assert len(entry["sha256"]) == 64


def test_baseline_snapshot_save(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    output = BaselineSnapshot(workspace).save("baseline.json")

    assert output.exists()
    assert output.name == "baseline.json"


def test_baseline_snapshot_is_deterministic_for_file_metadata(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    (workspace / "a.txt").write_text("A", encoding="utf-8")
    (workspace / "b.txt").write_text("B", encoding="utf-8")

    snapshot = BaselineSnapshot(workspace).capture()

    paths = [item["path"] for item in snapshot["files"]]

    assert paths == ["a.txt", "b.txt"]
