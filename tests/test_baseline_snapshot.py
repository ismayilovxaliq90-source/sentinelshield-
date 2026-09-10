from pathlib import Path
import subprocess

import pytest

from sentinelshield.baseline_snapshot import (
    BaselineSnapshotError,
    create_baseline_snapshot,
)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout


def init_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()

    git(root, "init")
    git(root, "config", "user.email", "test@example.com")
    git(root, "config", "user.name", "Test User")

    return root


def commit_initial(root: Path) -> None:
    git(root, "add", ".")
    git(root, "commit", "-m", "initial")


def test_snapshot_captures_repository_metadata(tmp_path):
    root = init_repo(tmp_path)

    source = root / "app.py"
    source.write_text(
        "print('hello')\n",
        encoding="utf-8",
    )

    commit_initial(root)

    snapshot = create_baseline_snapshot(root)

    assert snapshot.repository_root == str(root.resolve())
    assert snapshot.head
    assert snapshot.branch
    assert any(item.path == "app.py" for item in snapshot.files)
    assert snapshot.status == ()


def test_snapshot_from_nested_directory(tmp_path):
    root = init_repo(tmp_path)

    source = root / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    commit_initial(root)

    snapshot = create_baseline_snapshot(
        root / "src"
    )

    assert snapshot.repository_root == str(root.resolve())
    assert any(item.path == "src/app.py" for item in snapshot.files)


def test_snapshot_detects_working_tree_changes(tmp_path):
    root = init_repo(tmp_path)

    source = root / "app.py"
    source.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    commit_initial(root)

    source.write_text(
        "value = 2\n",
        encoding="utf-8",
    )

    snapshot = create_baseline_snapshot(root)

    assert snapshot.status
    assert any(
        line.endswith("app.py")
        for line in snapshot.status
    )


def test_snapshot_captures_untracked_file(tmp_path):
    root = init_repo(tmp_path)

    tracked = root / "app.py"
    tracked.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    commit_initial(root)

    untracked = root / "new.txt"
    untracked.write_text(
        "new\n",
        encoding="utf-8",
    )

    snapshot = create_baseline_snapshot(root)

    assert any(
        item.path == "new.txt"
        for item in snapshot.files
    )


def test_snapshot_fingerprint_changes_when_file_changes(tmp_path):
    root = init_repo(tmp_path)

    source = root / "app.py"
    source.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    commit_initial(root)

    first = create_baseline_snapshot(root)

    first_item = next(
        item
        for item in first.files
        if item.path == "app.py"
    )

    source.write_text(
        "value = 999\n",
        encoding="utf-8",
    )

    second = create_baseline_snapshot(root)

    second_item = next(
        item
        for item in second.files
        if item.path == "app.py"
    )

    assert first_item.fingerprint != second_item.fingerprint


def test_snapshot_json_is_serializable(tmp_path):
    root = init_repo(tmp_path)

    source = root / "app.py"
    source.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    commit_initial(root)

    snapshot = create_baseline_snapshot(root)

    payload = snapshot.to_json()

    assert '"repository_root"' in payload
    assert '"head"' in payload
    assert '"files"' in payload


def test_detached_head_is_supported(tmp_path):
    root = init_repo(tmp_path)

    source = root / "app.py"
    source.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    commit_initial(root)

    git(root, "checkout", "--detach", "HEAD")

    snapshot = create_baseline_snapshot(root)

    assert snapshot.head
    assert snapshot.branch is None


def test_invalid_start_path_fails(tmp_path):
    missing = tmp_path / "missing"

    with pytest.raises(BaselineSnapshotError):
        create_baseline_snapshot(missing)


def test_non_directory_start_path_fails(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text(
        "data",
        encoding="utf-8",
    )

    with pytest.raises(BaselineSnapshotError):
        create_baseline_snapshot(file_path)


def test_invalid_timeout_fails(tmp_path):
    root = init_repo(tmp_path)

    with pytest.raises(ValueError):
        create_baseline_snapshot(
            root,
            timeout=0,
        )


def test_symlink_fingerprint_is_supported(tmp_path):
    root = init_repo(tmp_path)

    target = root / "target.txt"
    target.write_text(
        "target\n",
        encoding="utf-8",
    )

    link = root / "link.txt"
    link.symlink_to("target.txt")

    git(root, "add", ".")
    git(root, "commit", "-m", "initial")

    snapshot = create_baseline_snapshot(root)

    link_item = next(
        item
        for item in snapshot.files
        if item.path == "link.txt"
    )

    assert link_item.kind == "symlink"
    assert link_item.fingerprint


def test_missing_tracked_file_fails_safely(tmp_path):
    root = init_repo(tmp_path)

    source = root / "app.py"
    source.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    commit_initial(root)
    source.unlink()

    # Git status contains the deleted tracked path. Snapshot creation
    # must reject a missing tracked file rather than silently accepting it.
    with pytest.raises(BaselineSnapshotError):
        create_baseline_snapshot(root)
