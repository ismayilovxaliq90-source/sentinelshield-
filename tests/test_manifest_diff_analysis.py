from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from sentinelshield.manifest_diff_analysis import (
    ManifestDependencyChange,
    ManifestDiff,
    ManifestDiffAnalysisError,
    ManifestDiffAnalysisResult,
    analyze_manifest_diff,
    analyze_manifest_diffs,
    validate_manifest_diff_analysis,
)


def init_repo(path: Path) -> None:
    subprocess.run(
        ["git", "init", "-q", "-b", "main"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "task217@example.invalid"],
        cwd=path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Task 217"],
        cwd=path,
        check=True,
    )


def test_python_manifest_version_update(tmp_path: Path) -> None:
    init_repo(tmp_path)

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[project]\n"
        'dependencies = ["requests==2.31.0"]\n',
        encoding="utf-8",
    )

    diff = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,2 +1,2 @@\n"
        " [project]\n"
        '-dependencies = ["requests==2.31.0"]\n'
        '+dependencies = ["requests==2.32.0"]\n'
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["pyproject.toml"],
    )

    assert result.changed_manifest_count == 1
    assert result.dependency_change_count == 1

    change = result.manifests[0].dependency_changes[0]
    assert change.name == "requests"
    assert change.old_version == "==2.31.0"
    assert change.new_version == "==2.32.0"
    assert change.change_type == "updated"


def test_package_json_dependency_addition(tmp_path: Path) -> None:
    init_repo(tmp_path)

    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1,4 @@\n"
        " {\n"
        '-  \"dependencies\": {}\n'
        '+  \"dependencies\": {\n'
        '+    \"express\": \"4.21.0\"\n'
        '+  }\n'
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["package.json"],
    )

    assert result.changed_manifest_count == 1
    assert any(
        item.name == "express"
        and item.change_type == "added"
        for item in result.manifests[0].dependency_changes
    )


def test_removed_dependency(tmp_path: Path) -> None:
    init_repo(tmp_path)

    manifest = tmp_path / "package.json"
    manifest.write_text(
        '{"dependencies":{"lodash":"4.17.20"}}',
        encoding="utf-8",
    )

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1 @@\n"
        '-{\"dependencies\":{\"lodash\":\"4.17.20\"}}\n'
        '+{\"dependencies\":{}}\n'
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["package.json"],
    )

    assert result.changed_manifest_count == 1


def test_unrelated_file_is_detected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    (tmp_path / "pyproject.toml").write_text(
        "[project]\n",
        encoding="utf-8",
    )

    diff = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1 +1,2 @@\n"
        " [project]\n"
        "+name = \"demo\"\n"
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1 +1,2 @@\n"
        " print('a')\n"
        "+print('b')\n"
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["pyproject.toml"],
    )

    assert "app.py" in result.unrelated_files


def test_unsupported_manifest_is_reported(tmp_path: Path) -> None:
    init_repo(tmp_path)

    (tmp_path / "custom.lock").write_text(
        "dependency\n",
        encoding="utf-8",
    )

    result = analyze_manifest_diff(
        tmp_path,
        "diff --git a/custom.lock b/custom.lock\n",
        ["custom.lock"],
    )

    assert result.unsupported_manifests == ("custom.lock",)


def test_manifest_path_traversal_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["../pyproject.toml"],
        )


def test_absolute_manifest_path_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            [str(tmp_path / "pyproject.toml")],
        )


def test_null_manifest_path_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["package.json\x00evil"],
        )


def test_missing_manifest_is_not_fabricated(tmp_path: Path) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["package.json"],
    )

    assert result.manifests == ()


def test_secret_redaction(tmp_path: Path) -> None:
    init_repo(tmp_path)

    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1 @@\n"
        "-token=super-secret-value\n"
        "+token=new-secret-value\n"
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["package.json"],
    )

    rendered = result.to_json()

    assert "super-secret-value" not in rendered
    assert "new-secret-value" not in rendered
    assert "<REDACTED>" in rendered


def test_large_diff_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "x" * 2_000_001,
            [],
        )


def test_result_serialization(tmp_path: Path) -> None:
    result = ManifestDiffAnalysisResult(
        repository_root=str(tmp_path),
        manifests=(
            ManifestDiff(
                path="pyproject.toml",
                manager="python",
                dependency_changes=(
                    ManifestDependencyChange(
                        name="requests",
                        old_version="==2.31.0",
                        new_version="==2.32.0",
                        change_type="updated",
                        line_number=4,
                    ),
                ),
            ),
        ),
    )

    payload = json.loads(result.to_json())

    assert payload["changed_manifest_count"] == 1
    assert payload["dependency_change_count"] == 1


def test_result_validation(tmp_path: Path) -> None:
    result = ManifestDiffAnalysisResult(
        repository_root=str(tmp_path),
    )

    assert validate_manifest_diff_analysis(result) is True


def test_result_validation_rejects_wrong_type() -> None:
    assert validate_manifest_diff_analysis(object()) is False


def test_alias_matches_primary_function(tmp_path: Path) -> None:
    init_repo(tmp_path)

    first = analyze_manifest_diff(
        tmp_path,
        "",
        [],
    )
    second = analyze_manifest_diffs(
        tmp_path,
        "",
        [],
    )

    assert first.to_dict() == second.to_dict()


def test_invalid_dependency_change_type() -> None:
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestDependencyChange(
            name="requests",
            old_version="1.0.0",
            new_version="2.0.0",
            change_type="invalid",
            line_number=1,
        )


def test_invalid_line_number() -> None:
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestDependencyChange(
            name="requests",
            old_version="1.0.0",
            new_version="2.0.0",
            change_type="updated",
            line_number=0,
        )


def test_symlink_manifest_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    real = tmp_path / "real.json"
    real.write_text("{}", encoding="utf-8")

    link = tmp_path / "package.json"
    link.symlink_to(real)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "diff --git a/package.json b/package.json\n",
            ["package.json"],
        )
