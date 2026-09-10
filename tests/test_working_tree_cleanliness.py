from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from sentinelshield.working_tree_cleanliness import (
    WorkingTreeChange,
    WorkingTreeCleanlinessError,
    WorkingTreeCleanlinessResult,
    check_working_tree_cleanliness,
    evaluate_working_tree_cleanliness,
    is_working_tree_clean,
    working_tree_cleanliness_evaluation,
)


def completed(
    args,
    *,
    stdout="",
    stderr="",
    returncode=0,
):
    return CompletedProcess(
        args=args,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_clean_working_tree(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout="",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert isinstance(result, WorkingTreeCleanlinessResult)
    assert result.valid is True
    assert result.clean is True
    assert result.changed is False
    assert result.change_count == 0
    assert result.changes == ()
    assert result.reason == "WORKING_TREE_CLEAN"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_modified_working_tree(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout=" M src/example.py\n",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.clean is False
    assert result.changed is True
    assert result.change_count == 1
    assert result.reason == "WORKING_TREE_DIRTY"

    assert result.changes[0].status == " M"
    assert result.changes[0].path == "src/example.py"
    assert result.changes[0].index_status == " "
    assert result.changes[0].worktree_status == "M"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_staged_change_is_dirty(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout="M  src/example.py\n",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.clean is False
    assert result.change_count == 1
    assert result.changes[0].index_status == "M"
    assert result.changes[0].worktree_status == " "


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_untracked_file_is_dirty(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout="?? new_file.py\n",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.clean is False
    assert result.change_count == 1
    assert result.changes[0].status == "??"
    assert result.changes[0].path == "new_file.py"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_deleted_file_is_dirty(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout=" D deleted.py\n",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.changes[0].worktree_status == "D"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_rename_is_dirty(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout="R  old.py -> new.py\n",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.change_count == 1
    assert result.changes[0].status == "R "
    assert result.changes[0].path == "old.py -> new.py"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_multiple_changes_are_counted(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout=(
                " M a.py\n"
                "M  b.py\n"
                "?? c.py\n"
                " D d.py\n"
            ),
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.clean is False
    assert result.changed is True
    assert result.change_count == 4
    assert [item.path for item in result.changes] == [
        "a.py",
        "b.py",
        "c.py",
        "d.py",
    ]


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_git_repository_root_is_used(mock_run, tmp_path):
    nested = tmp_path / "service" / "src"
    nested.mkdir(parents=True)

    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout="",
        ),
    ]

    result = evaluate_working_tree_cleanliness(nested)

    assert result.valid is True
    assert result.repository_root == str(tmp_path.resolve())


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_not_a_git_repository(mock_run, tmp_path):
    mock_run.return_value = completed(
        ["git", "rev-parse", "--show-toplevel"],
        returncode=128,
        stderr="fatal: not a git repository\n",
    )

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.clean is False
    assert result.reason == "NOT_A_GIT_REPOSITORY"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_git_unavailable(mock_run, tmp_path):
    mock_run.side_effect = FileNotFoundError

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.reason == "GIT_NOT_AVAILABLE"


def test_missing_repository_path(tmp_path):
    missing = tmp_path / "missing"

    result = evaluate_working_tree_cleanliness(missing)

    assert result.valid is False
    assert result.reason == "REPOSITORY_PATH_NOT_FOUND"


def test_repository_path_is_file(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("data", encoding="utf-8")

    result = evaluate_working_tree_cleanliness(file_path)

    assert result.valid is False
    assert result.reason == "REPOSITORY_PATH_NOT_DIRECTORY"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "\x00bad",
        None,
        123,
        b"bytes",
        True,
    ],
)
def test_invalid_repository_path(value):
    with pytest.raises(WorkingTreeCleanlinessError):
        evaluate_working_tree_cleanliness(value)


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        121,
        True,
        "10",
        None,
    ],
)
def test_invalid_timeout(tmp_path, timeout):
    with pytest.raises(WorkingTreeCleanlinessError):
        evaluate_working_tree_cleanliness(
            tmp_path,
            timeout=timeout,
        )


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_status_timeout(mock_run, tmp_path):
    import subprocess

    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        subprocess.TimeoutExpired(
            cmd=[
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            timeout=10,
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.reason == "WORKING_TREE_STATUS_TIMEOUT"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_status_command_failure(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            returncode=128,
            stderr="git failure\n",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is False
    assert result.reason == "WORKING_TREE_STATUS_FAILED"


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_ignored_files_are_not_reported_by_default(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout="",
        ),
    ]

    result = evaluate_working_tree_cleanliness(tmp_path)

    assert result.valid is True
    assert result.clean is True


@patch(
    "sentinelshield.working_tree_cleanliness.subprocess.run"
)
def test_git_commands_do_not_use_shell(mock_run, tmp_path):
    mock_run.side_effect = [
        completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        completed(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            stdout="",
        ),
    ]

    evaluate_working_tree_cleanliness(tmp_path)

    for call in mock_run.call_args_list:
        assert call.kwargs["shell"] is False
        assert call.kwargs["stdin"] is not None


def test_result_is_immutable():
    result = WorkingTreeCleanlinessResult(
        valid=True,
        repository_root="/repo",
        clean=True,
        changed=False,
        change_count=0,
        changes=(),
        return_code=0,
        reason="WORKING_TREE_CLEAN",
    )

    with pytest.raises(AttributeError):
        result.valid = False


def test_change_is_immutable():
    change = WorkingTreeChange(
        status=" M",
        path="file.py",
        index_status=" ",
        worktree_status="M",
    )

    with pytest.raises(AttributeError):
        change.path = "other.py"


def test_aliases_are_available():
    assert callable(working_tree_cleanliness_evaluation)
    assert callable(check_working_tree_cleanliness)
    assert callable(is_working_tree_clean)


def test_dataclass_change_structure():
    change = WorkingTreeChange(
        status="??",
        path="new.py",
        index_status="?",
        worktree_status="?",
    )

    assert change.status == "??"
    assert change.path == "new.py"
    assert change.index_status == "?"
    assert change.worktree_status == "?"
