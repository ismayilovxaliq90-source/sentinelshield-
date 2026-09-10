import json

import pytest

from sentinelshield.manifest_diff_analysis import (
    ManifestChange,
    ManifestChangeType,
    ManifestDiffAnalysisError,
    ManifestDiffResult,
    analyze_manifest_diff,
    analyze_manifest_mapping,
    validate_manifest_diff,
)


def test_no_changes_passes():
    result = analyze_manifest_diff([])

    assert result.passed is True
    assert result.is_safe is True
    assert result.changed_manifest_count == 0


def test_expected_manifest_change_passes():
    change = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
        added_dependencies=("requests",),
    )

    result = analyze_manifest_diff(
        [change],
        expected_manifest_paths=("package.json",),
        expected_added_dependencies=("requests",),
    )

    assert result.passed is True
    assert result.unexpected_manifest_paths == ()
    assert result.unexpected_added_dependencies == ()


def test_unexpected_manifest_path_fails():
    change = ManifestChange(
        "package-lock.json",
        ManifestChangeType.MODIFIED,
    )

    result = analyze_manifest_diff(
        [change],
        expected_manifest_paths=("package.json",),
    )

    assert result.passed is False
    assert result.unexpected_manifest_paths == (
        "package-lock.json",
    )


def test_unexpected_added_dependency_fails():
    change = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
        added_dependencies=("evil-package",),
    )

    result = analyze_manifest_diff(
        [change],
        expected_manifest_paths=("package.json",),
        expected_added_dependencies=("safe-package",),
    )

    assert result.passed is False
    assert result.unexpected_added_dependencies == (
        "evil-package",
    )


def test_unexpected_removed_dependency_fails():
    change = ManifestChange(
        "pyproject.toml",
        ManifestChangeType.MODIFIED,
        removed_dependencies=("critical-package",),
    )

    result = analyze_manifest_diff(
        [change],
        expected_manifest_paths=("pyproject.toml",),
    )

    assert result.passed is False
    assert result.unexpected_removed_dependencies == (
        "critical-package",
    )


def test_unexpected_modified_dependency_fails():
    change = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
        modified_dependencies=("unexpected-package",),
    )

    result = analyze_manifest_diff(
        [change],
        expected_manifest_paths=("package.json",),
    )

    assert result.passed is False
    assert result.unexpected_modified_dependencies == (
        "unexpected-package",
    )


def test_all_expected_dependency_categories_pass():
    change = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
        added_dependencies=("a",),
        removed_dependencies=("b",),
        modified_dependencies=("c",),
    )

    result = analyze_manifest_diff(
        [change],
        expected_manifest_paths=("package.json",),
        expected_added_dependencies=("a",),
        expected_removed_dependencies=("b",),
        expected_modified_dependencies=("c",),
    )

    assert result.passed is True


def test_generator_inputs_work():
    change = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
        added_dependencies=("a",),
    )

    result = analyze_manifest_diff(
        (item for item in [change]),
        expected_manifest_paths=(item for item in ["package.json"]),
        expected_added_dependencies=(item for item in ["a"]),
    )

    assert result.passed is True


def test_duplicate_change_paths_rejected():
    change_a = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
    )
    change_b = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
    )

    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff([change_a, change_b])


def test_absolute_path_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestChange(
            "/tmp/package.json",
            ManifestChangeType.MODIFIED,
        )


def test_parent_traversal_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestChange(
            "../package.json",
            ManifestChangeType.MODIFIED,
        )


def test_empty_path_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestChange(
            " ",
            ManifestChangeType.MODIFIED,
        )


def test_string_path_collection_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_diff(
            [],
            expected_manifest_paths="package.json",
        )


def test_string_dependency_collection_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestChange(
            "package.json",
            ManifestChangeType.MODIFIED,
            added_dependencies="requests",
        )


def test_duplicate_dependencies_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestChange(
            "package.json",
            ManifestChangeType.MODIFIED,
            added_dependencies=("requests", "requests"),
        )


def test_added_and_removed_same_dependency_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestChange(
            "package.json",
            ManifestChangeType.MODIFIED,
            added_dependencies=("requests",),
            removed_dependencies=("requests",),
        )


def test_invalid_change_type_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestChange(
            "package.json",
            "invalid",
        )


def test_mapping_analysis():
    result = analyze_manifest_mapping(
        {
            "package.json": {
                "change_type": "modified",
                "added_dependencies": ["requests"],
            }
        },
        expected_manifest_paths=["package.json"],
        expected_added_dependencies=["requests"],
    )

    assert result.passed is True
    assert result.manifest_changes[0].path == "package.json"


def test_mapping_unexpected_change():
    result = analyze_manifest_mapping(
        {
            "package.json": {
                "change_type": "modified",
                "added_dependencies": ["unexpected"],
            }
        },
        expected_manifest_paths=["package.json"],
    )

    assert result.passed is False
    assert result.unexpected_added_dependencies == ("unexpected",)


def test_mapping_invalid_entry_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        analyze_manifest_mapping(
            {"package.json": "invalid"}
        )


def test_serialization_is_json():
    change = ManifestChange(
        "package.json",
        ManifestChangeType.MODIFIED,
        added_dependencies=("requests",),
    )

    result = analyze_manifest_diff(
        [change],
        expected_manifest_paths=("package.json",),
        expected_added_dependencies=("requests",),
    )

    payload = result.to_json()
    decoded = json.loads(payload)

    assert decoded["passed"] is True
    assert decoded["manifest_changes"][0]["path"] == "package.json"


def test_validation_accepts_valid_result():
    result = analyze_manifest_diff([])

    assert validate_manifest_diff(result) is True


def test_validation_rejects_non_result():
    assert validate_manifest_diff(None) is False
    assert validate_manifest_diff({}) is False


def test_inconsistent_result_rejected():
    with pytest.raises(ManifestDiffAnalysisError):
        ManifestDiffResult(
            manifest_changes=(),
            expected_manifest_paths=(),
            expected_added_dependencies=(),
            expected_removed_dependencies=(),
            expected_modified_dependencies=(),
            unexpected_manifest_paths=("package.json",),
            unexpected_added_dependencies=(),
            unexpected_removed_dependencies=(),
            unexpected_modified_dependencies=(),
            passed=True,
        )


def test_no_manifest_changes_but_expected_path_is_safe():
    result = analyze_manifest_diff(
        [],
        expected_manifest_paths=("package.json",),
    )

    assert result.passed is True


def test_paths_are_sorted_deterministically():
    changes = [
        ManifestChange(
            "z/package.json",
            ManifestChangeType.MODIFIED,
        ),
        ManifestChange(
            "a/package.json",
            ManifestChangeType.MODIFIED,
        ),
    ]

    result = analyze_manifest_diff(
        changes,
        expected_manifest_paths=(
            "z/package.json",
            "a/package.json",
        ),
    )

    assert [item.path for item in result.manifest_changes] == [
        "a/package.json",
        "z/package.json",
    ]
