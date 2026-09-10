from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinelshield.execution_isolation import (
    ExecutionIsolation,
    ExecutionIsolationError,
    execute_isolated,
    prepare_execution_isolation,
)
from sentinelshield.temporary_workspace import (
    cleanup_temporary_workspace,
    prepare_temporary_workspace,
)


def make_workspace(tmp_path):
    return prepare_temporary_workspace(
        base_dir=tmp_path,
    )


def test_prepare_does_not_execute_command(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        isolation = prepare_execution_isolation(
            workspace,
            ["python", "-c", "raise SystemExit(99)"],
        )

        assert isinstance(
            isolation,
            ExecutionIsolation,
        )
        assert isolation.shell is False
        assert isolation.start_new_session is True
        assert isolation.cwd == workspace.path.resolve()
    finally:
        cleanup_temporary_workspace(workspace)


def test_string_command_is_rejected(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(TypeError):
            prepare_execution_isolation(
                workspace,
                "python -c pass",  # type: ignore[arg-type]
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_empty_command_is_rejected(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(ValueError):
            prepare_execution_isolation(
                workspace,
                [],
            )
    finally:
        cleanup_temporary_workspace(workspace)


@pytest.mark.parametrize(
    "command",
    [
        ["python", ""],
        ["python", "bad\x00argument"],
        ["python", None],
    ],
)
def test_invalid_command_arguments_are_rejected(
    tmp_path,
    command,
):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(
            (TypeError, ValueError)
        ):
            prepare_execution_isolation(
                workspace,
                command,
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_cwd_defaults_to_workspace(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        isolation = prepare_execution_isolation(
            workspace,
            ["true"],
        )

        assert isolation.cwd == workspace.path.resolve()
    finally:
        cleanup_temporary_workspace(workspace)


def test_relative_cwd_inside_workspace_is_allowed(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        child = workspace.path / "child"
        child.mkdir()

        isolation = prepare_execution_isolation(
            workspace,
            ["true"],
            cwd="child",
        )

        assert isolation.cwd == child.resolve()
    finally:
        cleanup_temporary_workspace(workspace)


def test_absolute_cwd_outside_workspace_is_rejected(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(ExecutionIsolationError):
            prepare_execution_isolation(
                workspace,
                ["true"],
                cwd=tmp_path,
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_path_traversal_cwd_is_rejected(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(ExecutionIsolationError):
            prepare_execution_isolation(
                workspace,
                ["true"],
                cwd="../../",
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_environment_is_restricted_to_allowlist(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        isolation = prepare_execution_isolation(
            workspace,
            ["true"],
            environment={
                "PATH": "/usr/bin",
                "LANG": "C",
            },
        )

        env = isolation.environment_dict()

        assert env["PATH"] == "/usr/bin"
        assert env["LANG"] == "C"
        assert "SECRET" not in env
    finally:
        cleanup_temporary_workspace(workspace)


def test_non_allowlisted_environment_is_rejected(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(ExecutionIsolationError):
            prepare_execution_isolation(
                workspace,
                ["true"],
                environment={
                    "PATH": "/usr/bin",
                    "SECRET": "value",
                },
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_environment_null_is_rejected(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(ValueError):
            prepare_execution_isolation(
                workspace,
                ["true"],
                environment={
                    "PATH": "/usr/bin",
                    "LANG": "bad\x00value",
                },
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_environment_allowlist_must_not_be_empty(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        with pytest.raises(ValueError):
            prepare_execution_isolation(
                workspace,
                ["true"],
                environment_allowlist=set(),
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_missing_path_is_allowed_only_if_explicit_environment_is_valid(
    tmp_path,
):
    workspace = make_workspace(tmp_path)

    try:
        isolation = prepare_execution_isolation(
            workspace,
            ["true"],
            environment={
                "PATH": "/usr/bin",
            },
        )

        assert isolation.environment_dict() == {
            "PATH": "/usr/bin"
        }
    finally:
        cleanup_temporary_workspace(workspace)


def test_to_dict_contains_security_flags(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        isolation = prepare_execution_isolation(
            workspace,
            ["true"],
            environment={
                "PATH": "/usr/bin",
            },
        )

        data = isolation.to_dict()

        assert data["shell"] is False
        assert data["start_new_session"] is True
        assert data["cwd"] == str(
            workspace.path.resolve()
        )
        assert data["command"] == ["true"]
    finally:
        cleanup_temporary_workspace(workspace)


def test_execute_isolation_requires_valid_object():
    with pytest.raises(TypeError):
        execute_isolated(None)  # type: ignore[arg-type]


def test_execute_isolation_rejects_non_positive_timeout(
    tmp_path,
):
    workspace = make_workspace(tmp_path)

    try:
        isolation = prepare_execution_isolation(
            workspace,
            ["true"],
            environment={
                "PATH": "/usr/bin",
            },
        )

        with pytest.raises(ValueError):
            execute_isolated(
                isolation,
                timeout=0,
            )
    finally:
        cleanup_temporary_workspace(workspace)


def test_execute_isolated_uses_workspace_cwd(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        isolation = prepare_execution_isolation(
            workspace,
            [
                "/bin/pwd",
            ],
            environment={
                "PATH": "/usr/bin:/bin",
            },
        )

        result = execute_isolated(
            isolation,
            timeout=10,
        )

        assert result.returncode == 0
        assert result.stdout.strip() == str(
            workspace.path.resolve()
        )
    finally:
        cleanup_temporary_workspace(workspace)


def test_execute_isolated_does_not_use_shell(tmp_path):
    workspace = make_workspace(tmp_path)

    try:
        # If shell=True were accidentally enabled, the shell
        # operator could be interpreted. With shell=False this
        # becomes an ordinary argument.
        isolation = prepare_execution_isolation(
            workspace,
            [
                "/bin/printf",
                "%s",
                "hello;touch SHOULD_NOT_EXIST",
            ],
            environment={
                "PATH": "/usr/bin:/bin",
            },
        )

        result = execute_isolated(
            isolation,
            timeout=10,
        )

        assert result.returncode == 0
        assert "hello;touch SHOULD_NOT_EXIST" in result.stdout
        assert not (
            workspace.path / "SHOULD_NOT_EXIST"
        ).exists()
    finally:
        cleanup_temporary_workspace(workspace)


def test_execute_isolated_can_read_only_workspace_content(
    tmp_path,
):
    workspace = make_workspace(tmp_path)

    try:
        source = workspace.path / "input.txt"
        source.write_text(
            "isolated-data",
            encoding="utf-8",
        )

        isolation = prepare_execution_isolation(
            workspace,
            [
                "/bin/cat",
                "input.txt",
            ],
            environment={
                "PATH": "/usr/bin:/bin",
            },
        )

        result = execute_isolated(
            isolation,
            timeout=10,
        )

        assert result.returncode == 0
        assert result.stdout == "isolated-data"
    finally:
        cleanup_temporary_workspace(workspace)
