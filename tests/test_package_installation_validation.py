from pathlib import Path

import pytest

from sentinelshield.package_installation_validation import (
    InstalledPackage,
    PackageInstallationRequest,
    PackageInstallationResult,
    PackageInstallationValidationError,
    build_installation_command,
    discover_installed_packages,
    expected_dependency_names,
    validate_installation_result,
    validate_request,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()

    (root / "package.json").write_text(
        """{
  "name": "fixture",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "is-number": "7.0.0"
  }
}""",
        encoding="utf-8",
    )

    (root / "package-lock.json").write_text(
        """{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "version": "1.0.0"
    }
  }
}""",
        encoding="utf-8",
    )

    return root


def create_installed_package(
    root: Path,
    name: str = "is-number",
    version: str = "7.0.0",
) -> Path:
    package_dir = root / "node_modules" / name
    package_dir.mkdir(parents=True)

    (package_dir / "package.json").write_text(
        (
            "{"
            f'"name":"{name}",'
            f'"version":"{version}"'
            "}"
        ),
        encoding="utf-8",
    )

    return package_dir


def test_build_installation_command():
    assert build_installation_command("npm") == (
        "npm",
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    )


def test_unknown_manager_is_rejected():
    with pytest.raises(PackageInstallationValidationError):
        build_installation_command("unknown")


def test_request_validation(tmp_path):
    root = make_repo(tmp_path)

    assert validate_request(
        PackageInstallationRequest(
            repository_root=root,
            manager="npm",
        )
    ) == root.resolve()


def test_expected_dependencies(tmp_path):
    root = make_repo(tmp_path)

    assert expected_dependency_names(root) == (
        "is-number",
    )


def test_missing_manifest_is_rejected(tmp_path):
    root = make_repo(tmp_path)
    (root / "package.json").unlink()

    with pytest.raises(PackageInstallationValidationError):
        validate_request(
            PackageInstallationRequest(
                repository_root=root,
            )
        )


def test_missing_lockfile_is_rejected(tmp_path):
    root = make_repo(tmp_path)
    (root / "package-lock.json").unlink()

    with pytest.raises(PackageInstallationValidationError):
        validate_request(
            PackageInstallationRequest(
                repository_root=root,
            )
        )


def test_invalid_timeout_is_rejected(tmp_path):
    root = make_repo(tmp_path)

    with pytest.raises(PackageInstallationValidationError):
        validate_request(
            PackageInstallationRequest(
                repository_root=root,
                timeout=0,
            )
        )


def test_symlink_manifest_is_rejected(tmp_path):
    root = make_repo(tmp_path)

    real = root / "real-package.json"
    real.write_text("{}", encoding="utf-8")

    package = root / "package.json"
    package.unlink()
    package.symlink_to(real)

    with pytest.raises(PackageInstallationValidationError):
        validate_request(
            PackageInstallationRequest(
                repository_root=root,
            )
        )


def test_discover_installed_package(tmp_path):
    root = make_repo(tmp_path)
    create_installed_package(root)

    packages = discover_installed_packages(root)

    assert len(packages) == 1
    assert packages[0].name == "is-number"
    assert packages[0].version == "7.0.0"


def test_missing_installed_package_is_rejected(tmp_path):
    root = make_repo(tmp_path)
    (root / "node_modules").mkdir()

    with pytest.raises(PackageInstallationValidationError):
        discover_installed_packages(root)


def test_installed_symlink_is_rejected(tmp_path):
    root = make_repo(tmp_path)
    node_modules = root / "node_modules"
    node_modules.mkdir()

    real = root / "real-package"
    real.mkdir()

    (real / "package.json").write_text(
        '{"name":"is-number","version":"7.0.0"}',
        encoding="utf-8",
    )

    (node_modules / "is-number").symlink_to(real)

    with pytest.raises(PackageInstallationValidationError):
        discover_installed_packages(root)


def test_result_validation():
    package = InstalledPackage(
        name="is-number",
        version="7.0.0",
        path=Path("/tmp/node_modules/is-number"),
    )

    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=(
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ),
        returncode=0,
        expected_packages=("is-number",),
        installed_packages=(package,),
        lockfile_present=True,
        installation_directory_present=True,
        stdout="",
        stderr="",
        timed_out=False,
        error=None,
    )

    assert validate_installation_result(result) is True


def test_result_count_mismatch_fails():
    result = PackageInstallationResult(
        success=True,
        manager="npm",
        command=("npm", "ci"),
        returncode=0,
        expected_packages=("a", "b"),
        installed_packages=(),
        lockfile_present=True,
        installation_directory_present=True,
        stdout="",
        stderr="",
        timed_out=False,
        error=None,
    )

    assert validate_installation_result(result) is False


def test_failed_installation_result_is_valid_failure():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=1,
        expected_packages=(),
        installed_packages=(),
        lockfile_present=True,
        installation_directory_present=False,
        stdout="",
        stderr="failure",
        timed_out=False,
        error="PACKAGE_INSTALLATION_FAILED",
    )

    assert validate_installation_result(result) is True


def test_timeout_result_is_invalid():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=None,
        expected_packages=(),
        installed_packages=(),
        lockfile_present=True,
        installation_directory_present=False,
        stdout="",
        stderr="",
        timed_out=True,
        error="PACKAGE_INSTALLATION_TIMEOUT",
    )

    assert validate_installation_result(result) is False


def test_result_serialization():
    result = PackageInstallationResult(
        success=False,
        manager="npm",
        command=("npm", "ci"),
        returncode=1,
        expected_packages=(),
        installed_packages=(),
        lockfile_present=True,
        installation_directory_present=False,
        stdout="",
        stderr="failure",
        timed_out=False,
        error="PACKAGE_INSTALLATION_FAILED",
    )

    data = result.to_dict()

    assert data["success"] is False
    assert data["manager"] == "npm"
    assert data["command"] == ["npm", "ci"]
    assert data["error"] == "PACKAGE_INSTALLATION_FAILED"
