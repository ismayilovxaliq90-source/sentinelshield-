from pathlib import Path
from unittest.mock import patch

import pytest

from sentinelshield.repository_state_validation import (
    RepositoryStateValidationError,
    RepositoryStateResult,
    check_repository_state,
    is_repository_state_valid,
    repository_state_validation,
    validate_repository_state,
)


def _completed(
    args,
    *,
    stdout="",
    stderr="",
    returncode=0,
):
    from subprocess import CompletedProcess

    return CompletedProcess(
        args=args,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _git_sequence(
    *,
    root="/tmp/repository",
    git_dir=".git",
    head="0123456789abcdef0123456789abcdef01234567",
    branch="main",
):
    return [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{root}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=f"{git_dir}\n",
        ),
        _completed(
            ["git", "rev-parse", "HEAD"],
            stdout=f"{head}\n",
        ),
        _completed(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            stdout=f"{branch}\n",
        ),
    ]


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_valid_repository_state(mock_run, tmp_path):
    root = tmp_path

    git_dir = root / ".git"
    git_dir.mkdir()

    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{root}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=".git\n",
        ),
        _completed(
            ["git", "rev-parse", "HEAD"],
            stdout="0123456789abcdef0123456789abcdef01234567\n",
        ),
        _completed(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            stdout="main\n",
        ),
    ]

    result = validate_repository_state(root)

    assert isinstance(result, RepositoryStateResult)
    assert result.valid is True
    assert result.repository_root == str(root.resolve())
    assert result.git_directory == str(git_dir.resolve())
    assert result.head == "0123456789abcdef0123456789abcdef01234567"
    assert result.branch == "main"
    assert result.detached_head is False
    assert result.git_version == "2.51.0"
    assert result.reason == "VALID_REPOSITORY_STATE"


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_nested_path_resolves_to_repository_root(mock_run, tmp_path):
    root = tmp_path
    nested = root / "service" / "src"
    nested.mkdir(parents=True)

    (root / ".git").mkdir()

    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{root}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=".git\n",
        ),
        _completed(
            ["git", "rev-parse", "HEAD"],
            stdout="0123456789abcdef0123456789abcdef01234567\n",
        ),
        _completed(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            stdout="main\n",
        ),
    ]

    result = validate_repository_state(nested)

    assert result.valid is True
    assert result.repository_root == str(root.resolve())


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_detached_head_is_reported_but_repository_remains_valid(
    mock_run,
    tmp_path,
):
    (tmp_path / ".git").mkdir()

    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=".git\n",
        ),
        _completed(
            ["git", "rev-parse", "HEAD"],
            stdout="0123456789abcdef0123456789abcdef01234567\n",
        ),
        _completed(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            returncode=1,
            stderr="fatal: ref HEAD is not a symbolic ref\n",
        ),
    ]

    result = validate_repository_state(tmp_path)

    assert result.valid is True
    assert result.detached_head is True
    assert result.branch is None
    assert result.reason == "VALID_REPOSITORY_STATE_DETACHED_HEAD"


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_git_unavailable(mock_run, tmp_path):
    mock_run.side_effect = FileNotFoundError

    result = validate_repository_state(tmp_path)

    assert result.valid is False
    assert result.reason == "GIT_NOT_AVAILABLE"


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_not_git_repository(mock_run, tmp_path):
    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            returncode=128,
            stderr="fatal: not a git repository\n",
        ),
    ]

    result = validate_repository_state(tmp_path)

    assert result.valid is False
    assert result.reason == "NOT_A_GIT_REPOSITORY"


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_invalid_head(mock_run, tmp_path):
    (tmp_path / ".git").mkdir()

    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=".git\n",
        ),
        _completed(
            ["git", "rev-parse", "HEAD"],
            stdout="not-a-sha\n",
        ),
    ]

    result = validate_repository_state(tmp_path)

    assert result.valid is False
    assert result.reason == "INVALID_HEAD"


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_git_directory_missing(mock_run, tmp_path):
    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=".git\n",
        ),
    ]

    result = validate_repository_state(tmp_path)

    assert result.valid is False
    assert result.reason == "GIT_DIRECTORY_MISSING"


def test_missing_repository_path(tmp_path):
    missing = tmp_path / "does-not-exist"

    with patch(
        "sentinelshield.repository_state_validation.subprocess.run"
    ) as mock_run:
        mock_run.return_value = _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        )

        result = validate_repository_state(missing)

    assert result.valid is False
    assert result.reason == "REPOSITORY_PATH_NOT_FOUND"


def test_file_as_repository_path(tmp_path):
    path = tmp_path / "file.txt"
    path.write_text("data", encoding="utf-8")

    with patch(
        "sentinelshield.repository_state_validation.subprocess.run"
    ) as mock_run:
        mock_run.return_value = _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        )

        result = validate_repository_state(path)

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
def test_invalid_path_input(value):
    with pytest.raises(RepositoryStateValidationError):
        validate_repository_state(value)


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
    with pytest.raises(RepositoryStateValidationError):
        validate_repository_state(tmp_path, timeout=timeout)


def test_alias_repository_state_validation():
    assert repository_state_validation is not None


def test_alias_check_repository_state():
    assert check_repository_state is not None


def test_boolean_api_exists():
    assert callable(is_repository_state_valid)


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_boolean_api_returns_true_for_valid_state(mock_run, tmp_path):
    (tmp_path / ".git").mkdir()

    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=".git\n",
        ),
        _completed(
            ["git", "rev-parse", "HEAD"],
            stdout="0123456789abcdef0123456789abcdef01234567\n",
        ),
        _completed(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            stdout="main\n",
        ),
    ]

    assert is_repository_state_valid(tmp_path) is True


@patch(
    "sentinelshield.repository_state_validation.subprocess.run"
)
def test_commands_never_use_shell(mock_run, tmp_path):
    (tmp_path / ".git").mkdir()

    mock_run.side_effect = [
        _completed(
            ["git", "--version"],
            stdout="git version 2.51.0\n",
        ),
        _completed(
            ["git", "rev-parse", "--show-toplevel"],
            stdout=f"{tmp_path}\n",
        ),
        _completed(
            ["git", "rev-parse", "--git-dir"],
            stdout=".git\n",
        ),
        _completed(
            ["git", "rev-parse", "HEAD"],
            stdout="0123456789abcdef0123456789abcdef01234567\n",
        ),
        _completed(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            stdout="main\n",
        ),
    ]

    validate_repository_state(tmp_path)

    for call in mock_run.call_args_list:
        assert call.kwargs["shell"] is False
        assert call.kwargs["stdin"] is not None


def test_result_is_immutable():
    result = RepositoryStateResult(
        valid=True,
        repository_root="/repo",
        git_directory="/repo/.git",
        head="0123456789abcdef0123456789abcdef01234567",
        branch="main",
        detached_head=False,
        git_version="2.51.0",
        return_code=0,
        reason="VALID_REPOSITORY_STATE",
    )

    with pytest.raises(AttributeError):
        result.valid = False
