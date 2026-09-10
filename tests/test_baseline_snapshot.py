import subprocess

from sentinelshield.baseline_snapshot import (
    BaselineFile,
    BaselineSnapshot,
    baseline_has_changes,
    create_baseline_snapshot,
)


def _git(repo, *args):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )


def _create_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    _git(repo, "init")

    tracked = repo / "tracked.txt"
    tracked.write_text("baseline")

    _git(repo, "add", "tracked.txt")

    _git(
        repo,
        "-c",
        "user.name=Task184",
        "-c",
        "user.email=task184@example.invalid",
        "commit",
        "-m",
        "baseline",
    )

    return repo


def test_clean_repository_baseline(tmp_path):
    repo = _create_repo(tmp_path)

    snapshot = create_baseline_snapshot(repo)

    assert snapshot.valid is True
    assert snapshot.repository_root == repo
    assert len(snapshot.head) == 40
    assert snapshot.branch is not None
    assert snapshot.detached_head is False
    assert snapshot.status == ()
    assert snapshot.reason == "BASELINE_SNAPSHOT_CREATED"
    assert baseline_has_changes(snapshot) is False


def test_baseline_contains_tracked_file(tmp_path):
    repo = _create_repo(tmp_path)

    snapshot = create_baseline_snapshot(repo)

    paths = {
        item.path
        for item in snapshot.files
    }

    assert "tracked.txt" in paths


def test_baseline_fingerprints_file(tmp_path):
    repo = _create_repo(tmp_path)

    snapshot = create_baseline_snapshot(repo)

    item = next(
        item
        for item in snapshot.files
        if item.path == "tracked.txt"
    )

    assert item.kind == "file"
    assert len(item.fingerprint) == 64


def test_baseline_records_existing_working_tree_change(tmp_path):
    repo = _create_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing change")

    snapshot = create_baseline_snapshot(repo)

    assert snapshot.valid is True
    assert snapshot.status != ()
    assert baseline_has_changes(snapshot) is True


def test_baseline_records_untracked_file(tmp_path):
    repo = _create_repo(tmp_path)

    untracked = repo / "new.txt"
    untracked.write_text("user file")

    snapshot = create_baseline_snapshot(repo)

    paths = {
        item.path
        for item in snapshot.files
    }

    assert "new.txt" in paths
    assert any(
        line.startswith("??")
        for line in snapshot.status
    )


def test_missing_path_fails(tmp_path):
    missing = tmp_path / "missing"

    snapshot = create_baseline_snapshot(missing)

    assert snapshot.valid is False
    assert snapshot.reason == "START_PATH_NOT_FOUND"


def test_file_path_fails(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("test")

    snapshot = create_baseline_snapshot(file_path)

    assert snapshot.valid is False
    assert snapshot.reason == "START_PATH_NOT_DIRECTORY"


def test_non_repository_fails(tmp_path):
    directory = tmp_path / "not-repository"
    directory.mkdir()

    snapshot = create_baseline_snapshot(directory)

    assert snapshot.valid is False
    assert snapshot.reason == "NOT_A_GIT_REPOSITORY"


def test_invalid_snapshot_has_no_changes():
    snapshot = BaselineSnapshot(
        repository_root=None if False else __import__("pathlib").Path("."),
        head="",
        branch=None,
        detached_head=False,
        status=(),
        files=(),
        valid=False,
        reason="TEST_INVALID",
    )

    assert snapshot.valid is False
    assert baseline_has_changes(snapshot) is False


def test_baseline_file_dataclass():
    item = BaselineFile(
        path="example.txt",
        kind="file",
        fingerprint="a" * 64,
    )

    assert item.path == "example.txt"
    assert item.kind == "file"
    assert item.fingerprint == "a" * 64


def test_multiple_files_are_recorded(tmp_path):
    repo = _create_repo(tmp_path)

    first = repo / "first.txt"
    second = repo / "second.txt"

    first.write_text("first")
    second.write_text("second")

    snapshot = create_baseline_snapshot(repo)

    paths = {
        item.path
        for item in snapshot.files
    }

    assert "first.txt" in paths
    assert "second.txt" in paths
    assert "tracked.txt" in paths


def test_snapshot_is_deterministic_for_unchanged_repository(tmp_path):
    repo = _create_repo(tmp_path)

    first = create_baseline_snapshot(repo)
    second = create_baseline_snapshot(repo)

    assert first.valid is True
    assert second.valid is True
    assert first.head == second.head
    assert first.branch == second.branch
    assert first.status == second.status
    assert first.files == second.files
