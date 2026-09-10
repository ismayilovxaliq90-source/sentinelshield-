from __future__ import annotations

from pathlib import Path

import pytest

from sentinelshield.lockfile_regeneration import (
    LockfileRegenerationError,
    LockfileRegenerationRequest,
    LockfileRegenerationResult,
    LockfileFingerprint,
    build_regeneration_command,
    expected_lockfile,
    validate_regeneration_result,
    validate_request,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def test_expected_npm_lockfile(tmp_path: Path):
    root = make_repo(tmp_path)

    assert expected_lockfile(root, "npm") == (
        root / "package-lock.json"
    )


def test_expected_pnpm_lockfile(tmp_path: Path):
    root = make_repo(tmp_path)

    assert expected_lockfile(root, "pnpm") == (
        root / "pnpm-lock.yaml"
    )


def test_expected_yarn_lockfile(tmp_path: Path):
    root = make_repo(tmp_path)

    assert expected_lockfile(root, "yarn") == (
        root / "yarn.lock"
    )


def test_expected_cargo_lockfile(tmp_path: Path):
    root = make_repo(tmp_path)

    assert expected_lockfile(root, "cargo") == (
        root / "Cargo.lock"
    )


def test_expected_go_lockfile(tmp_path: Path):
    root = make_repo(tmp_path)

    assert expected_lockfile(root, "go") == (
        root / "go.sum"
    )


def test_expected_composer_lockfile(tmp_path: Path):
    root = make_repo(tmp_path)

    assert expected_lockfile(root, "composer") == (
        root / "composer.lock"
    )


def test_expected_poetry_lockfile(tmp_path: Path):
    root = make_repo(tmp_path)

    assert expected_lockfile(root, "poetry") == (
        root / "poetry.lock"
    )


@pytest.mark.parametrize(
    "ecosystem,manager,manifest,expected",
    [
        (
            "npm",
            "npm",
            "package.json",
            (
                "npm",
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ),
        ),
        (
            "pnpm",
            "pnpm",
            "package.json",
            (
                "pnpm",
                "install",
                "--lockfile-only",
                "--ignore-scripts",
            ),
        ),
        (
            "yarn",
            "yarn",
            "package.json",
            (
                "yarn",
                "install",
                "--mode=skip-builds",
            ),
        ),
        (
            "cargo",
            "cargo",
            "Cargo.toml",
            (
                "cargo",
                "generate-lockfile",
            ),
        ),
        (
            "go",
            "go",
            "go.mod",
            (
                "go",
                "mod",
                "tidy",
            ),
        ),
        (
            "composer",
            "composer",
            "composer.json",
            (
                "composer",
                "update",
                "--lock",
                "--no-interaction",
                "--no-scripts",
            ),
        ),
        (
            "poetry",
            "poetry",
            "pyproject.toml",
            (
                "poetry",
                "lock",
            ),
        ),
    ],
)
def test_allowlisted_commands(
    ecosystem,
    manager,
    manifest,
    expected,
    tmp_path: Path,
):
    command = build_regeneration_command(
        ecosystem,
        manager,
        tmp_path / manifest,
    )

    assert command == expected


def test_unknown_ecosystem_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        expected_lockfile(
            make_repo(tmp_path),
            "unknown",
        )


def test_manager_must_match_ecosystem(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        build_regeneration_command(
            "npm",
            "pnpm",
            tmp_path / "package.json",
        )


def test_wrong_manifest_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        build_regeneration_command(
            "npm",
            "npm",
            tmp_path / "Cargo.toml",
        )


def test_manifest_must_exist(tmp_path: Path):
    root = make_repo(tmp_path)

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        package_manager="npm",
        manifest=root / "package.json",
        lockfile=root / "package-lock.json",
    )

    with pytest.raises(LockfileRegenerationError):
        validate_request(request)


def test_manifest_outside_repository_rejected(tmp_path: Path):
    root = make_repo(tmp_path)
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        package_manager="npm",
        manifest=manifest,
        lockfile=root / "package-lock.json",
    )

    with pytest.raises(LockfileRegenerationError):
        validate_request(request)


def test_lockfile_outside_repository_rejected(tmp_path: Path):
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    outside_lock = tmp_path / "package-lock.json"

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        package_manager="npm",
        manifest=manifest,
        lockfile=outside_lock,
    )

    with pytest.raises(LockfileRegenerationError):
        validate_request(request)


def test_lockfile_wrong_name_rejected(tmp_path: Path):
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        package_manager="npm",
        manifest=manifest,
        lockfile=root / "yarn.lock",
    )

    with pytest.raises(LockfileRegenerationError):
        validate_request(request)


def test_existing_lockfile_directory_rejected(tmp_path: Path):
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    lockfile = root / "package-lock.json"
    lockfile.mkdir()

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        package_manager="npm",
        manifest=manifest,
        lockfile=lockfile,
    )

    with pytest.raises(LockfileRegenerationError):
        validate_request(request)


def test_existing_lockfile_symlink_rejected(tmp_path: Path):
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    real_lock = root / "real-lock"
    real_lock.write_text("lock", encoding="utf-8")

    lockfile = root / "package-lock.json"
    lockfile.symlink_to(real_lock)

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        package_manager="npm",
        manifest=manifest,
        lockfile=lockfile,
    )

    with pytest.raises(LockfileRegenerationError):
        validate_request(request)


def test_missing_lockfile_is_valid_regeneration_target(
    tmp_path: Path,
):
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text(
        '{"name":"fixture","version":"1.0.0"}',
        encoding="utf-8",
    )

    request = LockfileRegenerationRequest(
        repository_root=root,
        ecosystem="npm",
        package_manager="npm",
        manifest=manifest,
        lockfile=root / "package-lock.json",
    )

    validated_root, validated_manifest, validated_lockfile, command = (
        validate_request(request)
    )

    assert validated_root == root.resolve()
    assert validated_manifest == manifest.resolve()
    assert validated_lockfile == (
        root / "package-lock.json"
    )
    assert command[0] == "npm"


def test_boolean_timeout_rejected(tmp_path: Path):
    with pytest.raises(TypeError):
        LockfileRegenerationRequest(
            repository_root=tmp_path,
            ecosystem="npm",
            package_manager="npm",
            manifest=tmp_path / "package.json",
            lockfile=tmp_path / "package-lock.json",
            timeout=True,
        )


def test_zero_timeout_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        LockfileRegenerationRequest(
            repository_root=tmp_path,
            ecosystem="npm",
            package_manager="npm",
            manifest=tmp_path / "package.json",
            lockfile=tmp_path / "package-lock.json",
            timeout=0,
        )


def test_empty_ecosystem_rejected(tmp_path: Path):
    with pytest.raises(LockfileRegenerationError):
        LockfileRegenerationRequest(
            repository_root=tmp_path,
            ecosystem=" ",
            package_manager="npm",
            manifest=tmp_path / "package.json",
            lockfile=tmp_path / "package-lock.json",
        )


def test_result_serialization():
    fingerprint = LockfileFingerprint(
        exists=True,
        is_file=True,
        is_symlink=False,
        size=10,
        sha256="abc",
    )

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
        before=fingerprint,
        after=fingerprint,
        stdout="ok",
        stderr="",
        reason="LOCKFILE_REGENERATED",
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["ecosystem"] == "npm"
    assert data["command"][0] == "npm"
    assert data["before"]["sha256"] == "abc"


def test_successful_result_validator():
    fingerprint = LockfileFingerprint(
        exists=True,
        is_file=True,
        is_symlink=False,
        size=10,
        sha256="abc",
    )

    result = LockfileRegenerationResult(
        success=True,
        ecosystem="npm",
        package_manager="npm",
        manifest=Path("/repo/package.json"),
        lockfile=Path("/repo/package-lock.json"),
        command=("npm", "install"),
        return_code=0,
        timed_out=False,
        changed=True,
        before=fingerprint,
        after=fingerprint,
        stdout="",
        stderr="",
        reason="LOCKFILE_REGENERATED",
    )

    assert validate_regeneration_result(result) is True


def test_failed_result_validator():
    fingerprint = LockfileFingerprint(
        exists=False,
        is_file=False,
        is_symlink=False,
        size=0,
        sha256=None,
    )

    result = LockfileRegenerationResult(
        success=False,
        ecosystem="npm",
        package_manager="npm",
        manifest=Path("/repo/package.json"),
        lockfile=Path("/repo/package-lock.json"),
        command=("npm", "install"),
        return_code=1,
        timed_out=False,
        changed=False,
        before=fingerprint,
        after=fingerprint,
        stdout="",
        stderr="failure",
        reason="REGENERATION_COMMAND_FAILED",
    )

    assert validate_regeneration_result(result) is False


def test_result_validator_rejects_wrong_type():
    with pytest.raises(TypeError):
        validate_regeneration_result(object())
