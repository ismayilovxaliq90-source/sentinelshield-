from pathlib import Path

import pytest

from sentinelshield.dependency_tree_regeneration import (
    DependencyTreeRegenerationError,
    DependencyTreeRequest,
    DependencyTreeResult,
    SUPPORTED_MANAGERS,
    build_dependency_tree_command,
    validate_dependency_tree_result,
    validate_request,
)


def make_repo(tmp_path: Path, manager: str) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()

    if manager in {"npm", "pnpm", "yarn"}:
        (root / "package.json").write_text(
            '{"name":"fixture","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}',
            encoding="utf-8",
        )
    elif manager == "go":
        (root / "go.mod").write_text(
            "module example.com/fixture\n\ngo 1.22\n",
            encoding="utf-8",
        )
    elif manager == "cargo":
        (root / "Cargo.toml").write_text(
            '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n',
            encoding="utf-8",
        )
    elif manager == "composer":
        (root / "composer.json").write_text(
            '{"name":"fixture/test","require":{}}',
            encoding="utf-8",
        )
    elif manager == "poetry":
        (root / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "fixture"\nversion = "0.1.0"\ndescription = ""\nauthors = []\n',
            encoding="utf-8",
        )

    return root


def test_supported_managers_are_known():
    assert {
        "npm",
        "pnpm",
        "yarn",
        "go",
        "cargo",
        "composer",
        "poetry",
    } <= SUPPORTED_MANAGERS


@pytest.mark.parametrize("manager", sorted(SUPPORTED_MANAGERS))
def test_command_is_sequence_and_shell_safe(manager):
    command = build_dependency_tree_command(manager)

    assert isinstance(command, tuple)
    assert command
    assert all(isinstance(item, str) for item in command)
    assert command[0] == manager


def test_unknown_manager_rejected():
    with pytest.raises(DependencyTreeRegenerationError):
        build_dependency_tree_command("unknown")


def test_request_validates_repository_and_manifest(tmp_path):
    root = make_repo(tmp_path, "npm")

    manifest = validate_request(
        DependencyTreeRequest(
            repository_root=root,
            manager="npm",
        )
    )

    assert manifest == root / "package.json"


def test_missing_manifest_rejected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()

    with pytest.raises(DependencyTreeRegenerationError):
        validate_request(
            DependencyTreeRequest(
                repository_root=root,
                manager="npm",
            )
        )


def test_symlink_manifest_rejected(tmp_path):
    root = make_repo(tmp_path, "npm")
    real = root / "real-package.json"
    real.write_text("{}", encoding="utf-8")

    package = root / "package.json"
    package.unlink()
    package.symlink_to(real)

    with pytest.raises(DependencyTreeRegenerationError):
        validate_request(
            DependencyTreeRequest(
                repository_root=root,
                manager="npm",
            )
        )


def test_invalid_timeout_rejected(tmp_path):
    root = make_repo(tmp_path, "npm")

    with pytest.raises(DependencyTreeRegenerationError):
        validate_request(
            DependencyTreeRequest(
                repository_root=root,
                manager="npm",
                timeout=0,
            )
        )


def test_success_result_validation():
    result = DependencyTreeResult(
        success=True,
        manager="npm",
        command=("npm", "ls", "--all", "--json", "--package-lock-only"),
        returncode=0,
        stdout="{}",
        stderr="",
        timed_out=False,
        tree={},
        fingerprint=None,
        error=None,
    )

    assert validate_dependency_tree_result(result) is True


def test_failed_result_validation():
    result = DependencyTreeResult(
        success=False,
        manager="npm",
        command=("npm", "ls"),
        returncode=1,
        stdout="",
        stderr="failure",
        timed_out=False,
        tree=None,
        fingerprint=None,
        error="DEPENDENCY_TREE_COMMAND_FAILED",
    )

    assert validate_dependency_tree_result(result) is True


def test_timeout_result_is_invalid():
    result = DependencyTreeResult(
        success=False,
        manager="npm",
        command=("npm", "ls"),
        returncode=None,
        stdout="",
        stderr="",
        timed_out=True,
        tree=None,
        fingerprint=None,
        error="DEPENDENCY_TREE_TIMEOUT",
    )

    assert validate_dependency_tree_result(result) is False


def test_result_serialization():
    result = DependencyTreeResult(
        success=True,
        manager="npm",
        command=("npm", "ls"),
        returncode=0,
        stdout="{}",
        stderr="",
        timed_out=False,
        tree={},
        fingerprint=None,
        error=None,
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["manager"] == "npm"
    assert data["command"] == ["npm", "ls"]
    assert data["tree"] == {}
