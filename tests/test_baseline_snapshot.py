import subprocess

from sentinelshield.baseline_snapshot import (
    BaselineSnapshot,
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


def _init_repo(tmp_path):
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


def test_clean_repository_snapshot(tmp_path):
    repo = _init_repo(tmp_path)

    snapshot = create_baseline_snapshot(repo)

    assert isinstance(snapshot, BaselineSnapshot)
    assert snapshot.valid is True
    assert snapshot.repository_root == repo.resolve()
    assert len(snapshot.head) == 40
    assert snapshot.branch
    assert snapshot.reason == "BASELINE_SNAPSHOT_CREATED"

    paths = {
        item.path
        for item in snapshot.files
    }

    assert "tracked.txt" in paths


def test_snapshot_contains_tracked_file_fingerprint(tmp_path):
    repo = _init_repo(tmp_path)

    snapshot = create_baseline_snapshot(repo)

    item = next(
        item
        for item in snapshot.files
        if item.path == "tracked.txt"
    )

    assert item.status == "  "
    assert item.fingerprint.startswith("FILE:")
    assert len(item.fingerprint) == 69


def test_snapshot_captures_preexisting_modified_file(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"
    tracked.write_text("pre-existing user change")

    snapshot = create_baseline_snapshot(repo)

    item = next(
        item
        for item in snapshot.files
        if item.path == "tracked.txt"
    )

    assert item.status == " M"
    assert item.fingerprint.startswith("FILE:")


def test_snapshot_captures_untracked_file(tmp_path):
    repo = _init_repo(tmp_path)

    new_file = repo / "user.txt"
    new_file.write_text("user content")

    snapshot = create_baseline_snapshot(repo)

    item = next(
        item
        for item in snapshot.files
        if item.path == "user.txt"
    )

    assert item.status == "??"
    assert item.fingerprint.startswith("FILE:")


def test_snapshot_fingerprint_changes_when_content_changes(tmp_path):
    repo = _init_repo(tmp_path)

    tracked = repo / "tracked.txt"

    first = create_baseline_snapshot(repo)

    first_item = next(
        item
        for item in first.files
        if item.path == "tracked.txt"
    )

    tracked.write_text("different content")

    second = create_baseline_snapshot(repo)

    second_item = next(
        item
        for item in second.files
        if item.path == "tracked.txt"
    )

    assert (
        first_item.fingerprint
        != second_item.fingerprint
    )


def test_missing_path_fails_closed(tmp_path):
    snapshot = create_baseline_snapshot(
        tmp_path / "missing"
    )

    assert snapshot.valid is False
    assert snapshot.reason == "START_PATH_NOT_FOUND"


def test_non_git_directory_fails_closed(tmp_path):
    directory = tmp_path / "plain"
    directory.mkdir()

    snapshot = create_baseline_snapshot(directory)

    assert snapshot.valid is False
    assert snapshot.reason == "NOT_A_GIT_REPOSITORY"


def test_snapshot_serialization(tmp_path):
    repo = _init_repo(tmp_path)

    snapshot = create_baseline_snapshot(repo)

    payload = snapshot.to_dict()

    assert payload["valid"] is True
    assert payload["head"] == snapshot.head
    assert isinstance(payload["files"], list)

    json_text = snapshot.to_json()

    assert '"valid": true' in json_text
    assert snapshot.head in json_text
