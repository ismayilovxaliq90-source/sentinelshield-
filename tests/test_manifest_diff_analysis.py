from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sentinelshield.manifest_diff_analysis import (
    ManifestDependencyChange,
    ManifestDiff,
    ManifestDiffAnalysisError,
    ManifestDiffAnalysisResult,
    analyze_manifest_diff,
    analyze_manifest_diffs,
    validate_manifest_diff,
    validate_manifest_diff_analysis,
)


def init_repo(root: Path) -> None:
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(
        "[core]\n",
        encoding="utf-8",
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

    assert result.repository_root == str(tmp_path.resolve())
    assert len(result.manifests) == 1
    assert result.manifests[0].manager == "python"

    changes = result.manifests[0].dependency_changes
    assert len(changes) == 1
    assert changes[0].name == "requests"
    assert changes[0].change_type == "updated"
    assert changes[0].old_version == "==2.31.0"
    assert changes[0].new_version == "==2.32.0"


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
        '-  "dependencies": {}\n'
        '+  "dependencies": {\n'
        '+    "express": "4.21.0"\n'
        '+  }\n'
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["package.json"],
    )

    changes = result.manifests[0].dependency_changes

    assert any(
        item.name == "express"
        and item.change_type == "added"
        and item.new_version == "4.21.0"
        for item in changes
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
        '-{"dependencies":{"lodash":"4.17.20"}}\n'
        '+{"dependencies":{}}\n'
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["package.json"],
    )

    changes = result.manifests[0].dependency_changes

    assert any(
        item.name == "lodash"
        and item.change_type == "removed"
        for item in changes
    )


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
        '+name = "demo"\n'
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

    assert result.unrelated_changes == ("app.py",)


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

    assert len(result.manifests) == 1
    assert result.manifests[0].supported is False
    assert result.manifests[0].manager is None


def test_missing_manifest_is_not_fabricated(tmp_path: Path) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["package.json"],
    )

    assert len(result.manifests) == 1
    assert result.manifests[0].path == "package.json"
    assert result.manifests[0].dependency_changes == ()


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

    assert "super-secret-value" not in result.redacted_diff
    assert "new-secret-value" not in result.redacted_diff
    assert "[REDACTED]" in result.redacted_diff


def test_result_serialization(tmp_path: Path) -> None:
    result = ManifestDiffAnalysisResult(
        repository_root=str(tmp_path.resolve()),
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
        unrelated_changes=(),
        redacted_diff="safe",
    )

    payload = result.to_dict()
    serialized = result.to_json()

    assert payload["repository_root"] == str(
        tmp_path.resolve()
    )
    assert json.loads(serialized)["safe"] is True


def test_result_validation(tmp_path: Path) -> None:
    result = ManifestDiffAnalysisResult(
        repository_root=str(tmp_path.resolve()),
        manifests=(),
        unrelated_changes=(),
        redacted_diff="",
    )

    assert validate_manifest_diff_analysis(result)
    assert validate_manifest_diff(result)


def test_absolute_repository_root_is_valid(tmp_path: Path) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path.resolve(),
        "",
        [],
    )

    assert Path(result.repository_root).is_absolute()


def test_relative_manifest_is_required(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["/tmp/package.json"],
        )


def test_parent_traversal_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["../package.json"],
        )


def test_empty_manifest_path_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            [""],
        )


def test_null_manifest_path_is_rejected(tmp_path: Path) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["package\x00.json"],
        )


def test_string_manifest_collection_is_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            "package.json",
        )


def test_bytes_manifest_collection_is_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            b"package.json",
        )


def test_symlink_manifest_is_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    target = tmp_path / "real.json"
    target.write_text("{}", encoding="utf-8")

    link = tmp_path / "package.json"

    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation unavailable")

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["package.json"],
        )


def test_outside_manifest_is_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["../outside.json"],
        )


def test_duplicate_manifest_paths_are_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["package.json", "package.json"],
        )


def test_invalid_repository_root_is_rejected(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            missing,
            "",
            [],
        )


def test_non_directory_repository_root_is_rejected(
    tmp_path: Path,
) -> None:
    file_path = tmp_path / "file"
    file_path.write_text("x", encoding="utf-8")

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            file_path,
            "",
            [],
        )


def test_large_diff_is_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            tmp_path,
            "x" * (2_000_000 + 1),
            [],
        )


def test_alias_matches_primary_function(
    tmp_path: Path,
) -> None:
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
            old_version=None,
            new_version="2.32.0",
            change_type="invalid",
            line_number=1,
        )


def test_bool_line_number_is_rejected() -> None:
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestDependencyChange(
            name="requests",
            old_version=None,
            new_version="2.32.0",
            change_type="added",
            line_number=True,
        )


def test_inconsistent_added_change_is_rejected() -> None:
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestDependencyChange(
            name="requests",
            old_version="2.31.0",
            new_version="2.32.0",
            change_type="added",
            line_number=1,
        )


def test_inconsistent_removed_change_is_rejected() -> None:
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestDependencyChange(
            name="requests",
            old_version=None,
            new_version=None,
            change_type="removed",
            line_number=1,
        )


def test_invalid_result_type() -> None:
    assert not validate_manifest_diff_analysis(
        object()
    )


def test_json_serialization_is_valid(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["package.json"],
    )

    payload = json.loads(result.to_json())

    assert payload["repository_root"] == str(
        tmp_path.resolve()
    )
    assert payload["manifests"][0]["path"] == "package.json"


def test_no_change_result_is_safe(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["package.json"],
    )

    assert result.safe is True
    assert result.unrelated_changes == ()


def test_multiple_manifests_preserve_order(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["package.json", "pyproject.toml"],
    )

    assert [
        item.path
        for item in result.manifests
    ] == [
        "package.json",
        "pyproject.toml",
    ]


def test_bearer_secret_is_redacted(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1 @@\n"
        '+Authorization: Bearer very-secret-token\n'
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["package.json"],
    )

    assert "very-secret-token" not in result.redacted_diff
    assert "[REDACTED]" in result.redacted_diff


def test_manifest_path_is_normalized(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["./package.json"],
    )

    assert result.manifests[0].path == "package.json"


def test_repository_root_must_not_be_relative(
    tmp_path: Path,
) -> None:
    old_cwd = Path.cwd()

    try:
        os.chdir(tmp_path)

        with pytest.raises(ManifestDiffAnalysisError):
            analyze_manifest_diff(
                ".",
                "",
                [],
            )
    finally:
        os.chdir(old_cwd)
