from __future__ import annotations

from pathlib import Path

import pytest

from sentinelshield.lockfile_regeneration import (
    LockfileRegenerationError,
    LockfileRegenerationRequest,
    LockfileRegenerationResult,
    LeastPrivilegeError if False else None,
    build_regeneration_command,
    expected_lockfile,
    validate_regeneration_request,
)


def test_expected_npm_lockfile(tmp_path: Path):
    assert expected_lockfile(tmp_path, "npm") == (
        tmp_path.resolve() / "package-lock.json"
    )


def test_expected_yarn_lockfile(tmp_path: Path):
    assert expected_lockfile(tmp_path, "yarn") == (
        tmp_path.resolve() / "yarn.lock"
    )


def test_expected_pnpm_lockfile(tmp_path: Path):
    assert expected_lockfile(tmp_path, "pnpm") == (
        tmp_path.resolve() / "pnpm-lock.yaml"
    )


def test_expected_cargo_lockfile(tmp_path: Path):
    assert expected_lockfile(tmp_path, "cargo") == (
        tmp_path.resolve() / "Cargo.lock"
    )


def test_expected_go_lockfile(tmp_path: Path):
    assert expected_lockfile(tmp_path, "go") == (
        tmp_path.resolve() / "go.sum"
    )


def test_expected_composer_lockfile(tmp_path: Path):
    assert expected_lockfile(tmp_path, "composer") == (
        tmp_path.resolve() / "composer.lock"
    )


def test_expected_poetry_lockfile(tmp_path: Path):
    assert expected_lockfile(tmp_path, "poetry") == (
        tmp_path.resolve() / "poetry.lock"
    )


def test_unknown_ecosystem_is_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        expected_lockfile(tmp_path, "unknown")


def test_npm_command_is_allowlisted(tmp_path: Path):
    command = build_regeneration_command(
        "npm",
        "npm",
        tmp_path / "package.json",
        tmp_path / "package-lock.json",
    )

    assert command == (
        "npm",
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    )


def test_cargo_command_is_allowlisted(tmp_path: Path):
    command = build_regeneration_command(
        "cargo",
        "cargo",
        tmp_path / "Cargo.toml",
        tmp_path / "Cargo.lock",
    )

    assert command == (
        "cargo",
        "generate-lockfile",
    )


def test_go_command_is_allowlisted(tmp_path: Path):
    command = build_regeneration_command(
        "go",
        "go",
        tmp_path / "go.mod",
        tmp_path / "go.sum",
    )

    assert command == (
        "go",
        "mod",
        "tidy",
    )


def test_manager_must_match_ecosystem(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        build_regeneration_command(
            "npm",
            "yarn",
            tmp_path / "package.json",
            tmp_path / "package-lock.json",
        )


def test_wrong_manifest_is_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        build_regeneration_command(
            "npm",
            "npm",
            tmp_path / "other.json",
            tmp_path / "package-lock.json",
        )


def test_repository_outside_manifest_is_rejected(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()

    manifest = tmp_path / "outside.json"
    manifest.write_text("{}", encoding="utf-8")

    lockfile = root / "package-lock.json"

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        manifest=manifest,
        lockfile=lockfile,
        package_manager="npm",
    )

    with pytest.raises(LockfileRegenerationError):
        validate_regeneration_request(request)


def test_repository_outside_lockfile_is_rejected(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    lockfile = tmp_path / "package-lock.json"

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        manifest=manifest,
        lockfile=lockfile,
        package_manager="npm",
    )

    with pytest.raises(LockfileRegenerationError):
        validate_regeneration_request(request)


def test_existing_lockfile_directory_is_rejected(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    lockfile = root / "package-lock.json"
    lockfile.mkdir()

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        manifest=manifest,
        lockfile=lockfile,
        package_manager="npm",
    )

    with pytest.raises(LockfileRegenerationError):
        validate_regeneration_request(request)


def test_existing_lockfile_symlink_is_rejected(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    real = root / "real-lock"
    real.write_text("lock", encoding="utf-8")

    lockfile = root / "package-lock.json"
    lockfile.symlink_to(real)

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        manifest=manifest,
        lockfile=lockfile,
        package_manager="npm",
    )

    with pytest.raises(LockfileRegenerationError):
        validate_regeneration_request(request)


def test_missing_lockfile_is_allowed_for_regeneration(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    lockfile = root / "package-lock.json"

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        manifest=manifest,
        lockfile=lockfile,
        package_manager="npm",
    )

    validated_root, validated_manifest, command = (
        validate_regeneration_request(request)
    )

    assert validated_root == root.resolve()
    assert validated_manifest == manifest.resolve()
    assert command[0] == "npm"


def test_boolean_timeout_is_rejected(tmp_path: Path):
    with pytest.raises(TypeError):
        LockfileRegenerationRequest(
            repository_root=tmp_path,
            ecosystem="npm",
            manifest=tmp_path / "package.json",
            lockfile=tmp_path / "package-lock.json",
            package_manager="npm",
            timeout=True,
        )


def test_zero_timeout_is_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        LockfileRegenerationRequest(
            repository_root=tmp_path,
            ecosystem="npm",
            manifest=tmp_path / "package.json",
            lockfile=tmp_path / "package-lock.json",
            package_manager="npm",
            timeout=0,
        )


def test_empty_manager_is_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        LockfileRegenerationRequest(
            repository_root=tmp_path,
            ecosystem="npm",
            manifest=tmp_path / "package.json",
            lockfile=tmp_path / "package-lock.json",
            package_manager="",
        )


def test_result_serialization():
    result = LockfileRegenerationResult(
        success=True,
        ecosystem="npm",
        package_manager="npm",
        manifest=Path("/repo/package.json"),
        lockfile=Path("/repo/package-lock.json"),
        command=(
            "npm",
            "install",
            "--package-lock-only",
        ),
        return_code=0,
        timed_out=False,
        changed=True,
        before=None,
        after=None,
        stdout="ok",
        stderr="",
        reason="LOCKFILE_REGENERATED",
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["command"][0] == "npm"
    assert data["return_code"] == 0
