from pathlib import Path
import pytest
from sentinelshield.environment_rollback import (
    EnvironmentRollbackInput,
    EnvironmentRollbackResult,
    environment_rollback,
)

def test_file_restore(tmp_path):
    root = tmp_path / "root"
    base = tmp_path / "base"
    root.mkdir()
    base.mkdir()
    (base / "a.txt").write_text("old")
    (root / "a.txt").write_text("new")
    r = environment_rollback(
        EnvironmentRollbackInput(root, base, ("a.txt",))
    )
    assert r.status == "PASS"
    assert (root / "a.txt").read_text() == "old"

def test_directory_restore(tmp_path):
    root = tmp_path / "root"
    base = tmp_path / "base"
    root.mkdir()
    base.mkdir()
    (base / "env").mkdir()
    (base / "env" / "x").write_text("old")
    r = environment_rollback(
        EnvironmentRollbackInput(root, base, ("env",))
    )
    assert r.status == "PASS"
    assert (root / "env" / "x").read_text() == "old"

def test_missing_baseline(tmp_path):
    root = tmp_path / "root"
    base = tmp_path / "base"
    root.mkdir()
    base.mkdir()
    r = environment_rollback(
        EnvironmentRollbackInput(root, base, ("missing.txt",))
    )
    assert r.status == "FAIL"
    assert r.missing_baseline == ("missing.txt",)

def test_invalid_input(tmp_path):
    with pytest.raises(TypeError):
        environment_rollback(None)

def test_invalid_root(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(ValueError):
        environment_rollback(
            EnvironmentRollbackInput(
                tmp_path / "missing", base, ()
            )
        )

def test_invalid_baseline(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ValueError):
        environment_rollback(
            EnvironmentRollbackInput(
                root, tmp_path / "missing", ()
            )
        )

def test_invalid_target_type(tmp_path):
    root = tmp_path / "root"
    base = tmp_path / "base"
    root.mkdir()
    base.mkdir()
    with pytest.raises(TypeError):
        environment_rollback(
            EnvironmentRollbackInput(root, base, ["a"])
        )

def test_absolute_target_rejected(tmp_path):
    root = tmp_path / "root"
    base = tmp_path / "base"
    root.mkdir()
    base.mkdir()
    with pytest.raises(ValueError):
        environment_rollback(
            EnvironmentRollbackInput(
                root, base, (str(tmp_path / "a"),)
            )
        )

def test_parent_traversal_rejected(tmp_path):
    root = tmp_path / "root"
    base = tmp_path / "base"
    root.mkdir()
    base.mkdir()
    with pytest.raises(ValueError):
        environment_rollback(
            EnvironmentRollbackInput(root, base, ("../a",))
        )

def test_result_shape(tmp_path):
    root = tmp_path / "root"
    base = tmp_path / "base"
    root.mkdir()
    base.mkdir()
    r = environment_rollback(
        EnvironmentRollbackInput(root, base, ())
    )
    assert isinstance(r, EnvironmentRollbackResult)
    assert r.status == "PASS"
