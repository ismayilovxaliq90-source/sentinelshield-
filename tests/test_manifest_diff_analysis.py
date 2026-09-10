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
    validate_manifest_diff,
    validate_manifest_diff_analysis,
)


def init_repo(root: Path) -> None:
    (root / ".git").mkdir()


def test_python_manifest_version_update(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    (tmp_path / "pyproject.toml").write_text(
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

    assert Path(
        result.repository_root
    ).is_absolute()

    change = result.manifests[0].dependency_changes[0]

    assert change.name == "requests"
    assert change.old_version == "==2.31.0"
    assert change.new_version == "==2.32.0"
    assert change.change_type == "updated"


def test_package_json_dependency_addition(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    (tmp_path / "package.json").write_text(
        "{}",
        encoding="utf-8",
    )

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

    assert any(
        item.name == "express"
        and item.change_type == "added"
        for item in (
            result.manifests[0]
            .dependency_changes
        )
    )


def test_removed_dependency(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    (tmp_path / "package.json").write_text(
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

    assert any(
        item.name == "lodash"
        and item.change_type == "removed"
        for item in (
            result.manifests[0]
            .dependency_changes
        )
    )


def test_unrelated_file_is_detected(
    tmp_path: Path,
) -> None:
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

    assert result.unrelated_changes == (
        "app.py",
    )


def test_unsupported_manifest(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    (tmp_path / "custom.lock").write_text(
        "data",
        encoding="utf-8",
    )

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["custom.lock"],
    )

    assert result.manifests[0].supported is False
    assert result.manifests[0].manager is None


def test_missing_manifest_is_not_fabricated(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        ["package.json"],
    )

    assert result.manifests[0].path == "package.json"
    assert result.manifests[0].dependency_changes == ()


def test_secret_redaction(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

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

    assert "super-secret-value" not in (
        result.redacted_diff
    )
    assert "new-secret-value" not in (
        result.redacted_diff
    )
    assert "[REDACTED]" in result.redacted_diff


def test_result_serialization(
    tmp_path: Path,
) -> None:
    result = ManifestDiffAnalysisResult(
        repository_root=str(
            tmp_path.resolve()
        ),
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
        unrelated_changes=(),
        redacted_diff="safe",
    )

    data = json.loads(
        result.to_json()
    )

    assert data["safe"] is True
    assert data["repository_root"] == str(
        tmp_path.resolve()
    )


def test_result_validation(
    tmp_path: Path,
) -> None:
    result = ManifestDiffAnalysisResult(
        repository_root=str(
            tmp_path.resolve()
        ),
        manifests=(),
        unrelated_changes=(),
        redacted_diff="",
    )

    assert validate_manifest_diff_analysis(
        result
    )
    assert validate_manifest_diff(result)


def test_absolute_manifest_path_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["/tmp/package.json"],
        )


def test_parent_traversal_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["../package.json"],
        )


def test_duplicate_paths_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        analyze_manifest_diff(
            tmp_path,
            "",
            [
                "package.json",
                "package.json",
            ],
        )


def test_string_collection_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        analyze_manifest_diff(
            tmp_path,
            "",
            "package.json",
        )


def test_symlink_rejected(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    target = tmp_path / "real.json"
    target.write_text(
        "{}",
        encoding="utf-8",
    )

    link = tmp_path / "package.json"

    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip(
            "Symlink creation unavailable"
        )

    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        analyze_manifest_diff(
            tmp_path,
            "",
            ["package.json"],
        )


def test_invalid_repository_root_rejected(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        analyze_manifest_diff(
            missing,
            "",
            [],
        )


def test_invalid_dependency_change_type() -> None:
    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        ManifestDependencyChange(
            name="requests",
            old_version=None,
            new_version="2.32.0",
            change_type="invalid",
            line_number=1,
        )


def test_bool_line_number_rejected() -> None:
    with pytest.raises(
        ManifestDiffAnalysisError
    ):
        ManifestDependencyChange(
            name="requests",
            old_version=None,
            new_version="2.32.0",
            change_type="added",
            line_number=True,
        )


def test_invalid_result_type() -> None:
    assert not validate_manifest_diff_analysis(
        object()
    )


def test_alias_matches_primary(
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


def test_bearer_redaction(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1 +1 @@\n"
        "+Authorization: Bearer very-secret-token\n"
    )

    result = analyze_manifest_diff(
        tmp_path,
        diff,
        ["package.json"],
    )

    assert "very-secret-token" not in (
        result.redacted_diff
    )
    assert "[REDACTED]" in result.redacted_diff


def test_no_change_is_safe(
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


def test_multiple_manifests_keep_order(
    tmp_path: Path,
) -> None:
    init_repo(tmp_path)

    result = analyze_manifest_diff(
        tmp_path,
        "",
        [
            "package.json",
            "pyproject.toml",
        ],
    )

    assert [
        item.path
        for item in result.manifests
    ] == [
        "package.json",
        "pyproject.toml",
    ]
