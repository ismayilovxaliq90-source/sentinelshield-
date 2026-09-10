from __future__ import annotations

import json
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


def make_repo(tmp_path: Path) -> Path:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    return tmp_path


def python_update_diff() -> str:
    return (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "index 1111111..2222222 100644\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,2 +1,2 @@\n"
        " [project]\n"
        '-dependencies = [\"requests==2.31.0\"]\n'
        '+dependencies = [\"requests==2.32.0\"]\n'
    )


def test_clean_diff_has_no_manifest_changes(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    result = analyze_manifest_diff(
        root,
        "",
        ["pyproject.toml"],
    )

    assert result.changed_manifest_count == 0
    assert result.dependency_change_count == 0
    assert result.has_dependency_changes is False


def test_python_dependency_version_update(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    manifest = root / "pyproject.toml"
    manifest.write_text(
        "[project]\n"
        'dependencies = ["requests==2.31.0"]\n',
        encoding="utf-8",
    )

    result = analyze_manifest_diff(
        root,
        python_update_diff(),
        ["pyproject.toml"],
    )

    assert result.changed_manifest_count == 1
    assert result.dependency_change_count == 1

    manifest_result = result.manifests[0]

    assert manifest_result.manager == "python"

    change = manifest_result.dependency_changes[0]

    assert change.name == "requests"
    assert change.old_version == "==2.31.0"
    assert change.new_version == "==2.32.0"
    assert change.change_type == "updated"


def test_npm_dependency_addition(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text(
        "{}",
        encoding="utf-8",
    )

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1,1 +1,4 @@\n"
        " {\n"
        '-  \"dependencies\": {}\n'
        '+  \"dependencies\": {\n'
        '+    \"express\": \"4.21.0\"\n'
        '+  }\n'
    )

    result = analyze_manifest_diff(
        root,
        diff,
        ["package.json"],
    )

    assert result.changed_manifest_count == 1
    assert result.manifests[0].manager == "npm"

    changes = result.manifests[0].dependency_changes

    assert any(
        item.name == "express"
        and item.change_type == "added"
        and item.new_version == "4.21.0"
        for item in changes
    )


def test_dependency_removal_is_detected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    manifest = root / "package.json"
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
        root,
        diff,
        ["package.json"],
    )

    assert result.changed_manifest_count == 1


def test_unrelated_file_is_separated(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    (root / "pyproject.toml").write_text(
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
        root,
        diff,
        ["pyproject.toml"],
    )

    assert "app.py" in result.unrelated_files


def test_multiple_manifest_types(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    (root / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        "[project]\n",
        encoding="utf-8",
    )

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1,3 @@\n"
        " {}\n"
        '+  "dependencies": {"axios": "1.8.0"}\n'
        "diff --git a/pyproject.toml "
        "b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1 +1,2 @@\n"
        " [project]\n"
        '+dependencies = ["requests==2.32.0"]\n'
    )

    result = analyze_manifest_diff(
        root,
        diff,
        [
            "package.json",
            "pyproject.toml",
        ],
    )

    assert result.changed_manifest_count == 2
    assert {
        item.manager
        for item in result.manifests
    } == {"npm", "python"}


def test_unsupported_manifest_is_reported(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    result = analyze_manifest_diff(
        root,
        "diff --git a/custom.lock b/custom.lock\n",
        ["custom.lock"],
    )

    assert result.unsupported_manifests == (
        "custom.lock",
    )


def test_missing_manifest_diff_is_not_fabricated(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    result = analyze_manifest_diff(
        root,
        "",
        ["package.json"],
    )

    assert result.manifests == ()


def test_path_traversal_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "",
            ["../package.json"],
        )


def test_absolute_path_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "",
            [str(root / "package.json")],
        )


def test_null_path_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "",
            ["package.json\x00evil"],
        )


def test_string_paths_container_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "",
            "package.json",
        )


def test_bytes_paths_container_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "",
            b"package.json",
        )


def test_symlink_manifest_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    real = root / "real.json"
    real.write_text(
        "{}",
        encoding="utf-8",
    )

    link = root / "package.json"
    link.symlink_to(real)

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "diff --git a/package.json b/package.json\n",
            ["package.json"],
        )


def test_repository_outside_manifest_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    outside = tmp_path.parent / "package.json"
    outside.write_text(
        "{}",
        encoding="utf-8",
    )

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "",
            ["../package.json"],
        )


def test_secret_values_are_redacted(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text(
        "{}",
        encoding="utf-8",
    )

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1,2 @@\n"
        " {}\n"
        "+token=super-secret-value\n"
        "+password=another-secret-value\n"
    )

    result = analyze_manifest_diff(
        root,
        diff,
        ["package.json"],
    )

    rendered = result.to_json()

    assert "super-secret-value" not in rendered
    assert "another-secret-value" not in rendered
    assert "<REDACTED>" in rendered


def test_bearer_secret_is_redacted(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text(
        "{}",
        encoding="utf-8",
    )

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1,2 @@\n"
        " {}\n"
        "+token=BearerVerySecret123\n"
    )

    result = analyze_manifest_diff(
        root,
        diff,
        ["package.json"],
    )

    assert "BearerVerySecret123" not in result.to_json()


def test_large_diff_is_rejected(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            root,
            "x" * (
                2_000_000 + 1
            ),
            [],
        )


def test_invalid_repository_is_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        analyze_manifest_diff(
            tmp_path,
            "",
            [],
        )


def test_malformed_hunk_is_reported(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    manifest = root / "package.json"
    manifest.write_text(
        "{}",
        encoding="utf-8",
    )

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "NOT-A-VALID-HUNK\n"
        "+garbage\n"
    )

    result = analyze_manifest_diff(
        root,
        diff,
        ["package.json"],
    )

    assert result.changed_manifest_count == 1
    assert "package.json" in result.malformed_manifests
    assert result.is_safe is False


def test_duplicate_manifest_paths_are_deduplicated(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    manifest = root / "pyproject.toml"
    manifest.write_text(
        "[project]\n",
        encoding="utf-8",
    )

    result = analyze_manifest_diff(
        root,
        "",
        [
            "pyproject.toml",
            "pyproject.toml",
        ],
    )

    assert result.changed_manifest_count == 0
    assert result.unsupported_manifests == ()


def test_result_serialization(
    tmp_path: Path,
) -> None:
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
                        line_number=2,
                    ),
                ),
            ),
        ),
    )

    payload = json.loads(
        result.to_json()
    )

    assert payload[
        "changed_manifest_count"
    ] == 1

    assert payload[
        "dependency_change_count"
    ] == 1

    assert payload[
        "manifests"
    ][0]["manager"] == "python"


def test_result_validation(
    tmp_path: Path,
) -> None:
    result = ManifestDiffAnalysisResult(
        repository_root=str(tmp_path),
    )

    assert validate_manifest_diff_analysis(
        result
    ) is True


def test_wrong_result_type_fails_validation() -> None:
    assert validate_manifest_diff_analysis(
        object()
    ) is False


def test_invalid_change_type_is_rejected() -> None:
    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        ManifestDependencyChange(
            name="requests",
            old_version="1.0.0",
            new_version="2.0.0",
            change_type="invalid",
            line_number=1,
        )


def test_invalid_line_number_is_rejected() -> None:
    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        ManifestDependencyChange(
            name="requests",
            old_version="1.0.0",
            new_version="2.0.0",
            change_type="updated",
            line_number=0,
        )


def test_boolean_line_number_is_rejected() -> None:
    with pytest.raises(
        ManifestDiffAnalysisError,
    ):
        ManifestDependencyChange(
            name="requests",
            old_version="1.0.0",
            new_version="2.0.0",
            change_type="updated",
            line_number=True,
        )


def test_alias_matches_primary_function(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    first = analyze_manifest_diff(
        root,
        "",
        [],
    )

    second = analyze_manifest_diffs(
        root,
        "",
        [],
    )

    assert first.to_dict() == second.to_dict()


def test_safe_result_has_no_malformed_manifests(
    tmp_path: Path,
) -> None:
    root = make_repo(tmp_path)

    result = analyze_manifest_diff(
        root,
        python_update_diff(),
        ["pyproject.toml"],
    )

    assert result.is_safe is True
