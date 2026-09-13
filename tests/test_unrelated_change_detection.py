import pytest

from sentinelshield.unrelated_change_detection import (
    UnrelatedChangeDetectionInput,
    detect_unrelated_changes,
)


def test_allowed_file_is_related():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=("pyproject.toml",),
            allowed_files=("pyproject.toml",),
        )
    )

    assert result.has_unrelated_changes is False
    assert result.related[0].reason == (
        "CHANGE_WITHIN_REMEDIATION_SCOPE"
    )


def test_unknown_file_is_unrelated():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=("README.md",),
            allowed_files=("pyproject.toml",),
        )
    )

    assert result.has_unrelated_changes is True
    assert result.unrelated[0].path == "README.md"
    assert result.unrelated[0].reason == (
        "CHANGE_OUTSIDE_REMEDIATION_SCOPE"
    )


def test_allowed_prefix_covers_nested_files():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=(
                "src/sentinelshield/a.py",
                "src/sentinelshield/b.py",
            ),
            allowed_files=(),
            allowed_prefixes=("src/sentinelshield",),
        )
    )

    assert result.has_unrelated_changes is False
    assert len(result.related) == 2


def test_similar_prefix_is_not_accepted():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=("src/sentinelshield-extra/a.py",),
            allowed_files=(),
            allowed_prefixes=("src/sentinelshield",),
        )
    )

    assert result.has_unrelated_changes is True


def test_results_are_sorted():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=("z.txt", "a.txt", "m.txt"),
            allowed_files=(),
        )
    )

    assert [item.path for item in result.changes] == [
        "a.txt",
        "m.txt",
        "z.txt",
    ]


def test_duplicate_changes_are_removed():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=(
                "README.md",
                "./README.md",
                "README.md",
            ),
            allowed_files=(),
        )
    )

    assert len(result.changes) == 1


def test_path_separators_are_normalized():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=("src\\app.py",),
            allowed_files=("src/app.py",),
        )
    )

    assert result.has_unrelated_changes is False


def test_change_type_is_detected():
    result = detect_unrelated_changes(
        UnrelatedChangeDetectionInput(
            changed_files=("package-lock.json",),
            allowed_files=(),
        )
    )

    assert result.unrelated[0].change_type == "CONFIGURATION"


def test_invalid_input_is_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_UNRELATED_CHANGE_DETECTION_INPUT",
    ):
        detect_unrelated_changes(None)


def test_non_string_changed_file_is_rejected():
    with pytest.raises(
        TypeError,
        match="CHANGED_FILE_MUST_BE_STRING",
    ):
        detect_unrelated_changes(
            UnrelatedChangeDetectionInput(
                changed_files=(123,),
                allowed_files=(),
            )
        )
