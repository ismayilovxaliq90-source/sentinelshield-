from __future__ import annotations

import json

import pytest

from sentinelshield.lockfile_diff_analysis import (
    LockfileDiffAnalysisError,
    LockfileDiffState,
    LockfileEntry,
    analyze_lockfile_content,
    analyze_lockfile_diff,
    validate_lockfile_diff_result,
)


def test_no_change():
    result = analyze_lockfile_diff(
        [LockfileEntry("requests", "2.32.0")],
        [LockfileEntry("requests", "2.32.0")],
    )

    assert result.state is LockfileDiffState.NO_CHANGE
    assert result.valid
    assert not result.has_changes
    assert result.is_safe


def test_added_dependency():
    result = analyze_lockfile_diff(
        [LockfileEntry("requests", "2.32.0")],
        [
            LockfileEntry("requests", "2.32.0"),
            LockfileEntry("urllib3", "2.5.0"),
        ],
        changed_lockfiles=("package-lock.json",),
        expected_changes=("ADD:urllib3:2.5.0",),
    )

    assert result.state is LockfileDiffState.EXPECTED_CHANGE
    assert result.valid
    assert [x.name for x in result.added_entries] == ["urllib3"]
    assert result.unexpected_changes == ()


def test_removed_dependency():
    result = analyze_lockfile_diff(
        [
            LockfileEntry("requests", "2.32.0"),
            LockfileEntry("urllib3", "2.4.0"),
        ],
        [LockfileEntry("requests", "2.32.0")],
        changed_lockfiles=("package-lock.json",),
        expected_changes=("REMOVE:urllib3:2.4.0",),
    )

    assert result.state is LockfileDiffState.EXPECTED_CHANGE
    assert result.removed_entries[0].name == "urllib3"


def test_version_change():
    baseline = [
        LockfileEntry("requests", "2.31.0"),
    ]
    current = [
        LockfileEntry("requests", "2.32.0"),
    ]

    result = analyze_lockfile_diff(
        baseline,
        current,
        changed_lockfiles=("package-lock.json",),
        expected_changes=("CHANGE:requests:2.31.0->2.32.0",),
    )

    assert result.state is LockfileDiffState.EXPECTED_CHANGE
    assert result.changed_entries[0].is_version_changed


def test_unexpected_dependency_change_fails():
    result = analyze_lockfile_diff(
        [LockfileEntry("requests", "2.31.0")],
        [LockfileEntry("requests", "2.32.0")],
        changed_lockfiles=("package-lock.json",),
        expected_changes=(),
    )

    assert result.state is LockfileDiffState.UNEXPECTED_CHANGE
    assert not result.valid
    assert result.unexpected_changes


def test_mixed_expected_and_unexpected_changes():
    result = analyze_lockfile_diff(
        [
            LockfileEntry("requests", "2.31.0"),
            LockfileEntry("urllib3", "2.4.0"),
        ],
        [
            LockfileEntry("requests", "2.32.0"),
            LockfileEntry("urllib3", "2.5.0"),
        ],
        changed_lockfiles=("package-lock.json",),
        expected_changes=("CHANGE:requests:2.31.0->2.32.0",),
    )

    assert result.state is LockfileDiffState.UNEXPECTED_CHANGE
    assert not result.valid
    assert len(result.unexpected_changes) == 1


def test_duplicate_entries_are_normalized():
    result = analyze_lockfile_diff(
        [
            LockfileEntry("requests", "2.32.0"),
            LockfileEntry("requests", "2.32.0"),
        ],
        [LockfileEntry("requests", "2.32.0")],
    )

    assert result.state is LockfileDiffState.NO_CHANGE


def test_mapping_input():
    result = analyze_lockfile_diff(
        [{"name": "requests", "version": "2.31.0"}],
        [{"name": "requests", "version": "2.32.0"}],
        changed_lockfiles=("package-lock.json",),
        expected_changes=("CHANGE:requests:2.31.0->2.32.0",),
    )

    assert result.valid


def test_generator_input():
    result = analyze_lockfile_diff(
        (LockfileEntry("a", "1.0.0") for _ in range(1)),
        (LockfileEntry("a", "1.1.0") for _ in range(1)),
        changed_lockfiles=("pnpm-lock.yaml",),
        expected_changes=("CHANGE:a:1.0.0->1.1.0",),
    )

    assert result.state is LockfileDiffState.EXPECTED_CHANGE


@pytest.mark.parametrize(
    "path",
    [
        "/absolute/package-lock.json",
        "../package-lock.json",
        "a/../../package-lock.json",
        ".",
        "",
        "   ",
        "a\\package-lock.json",
    ],
)
def test_invalid_lockfile_path(path):
    with pytest.raises(LockfileDiffAnalysisError):
        analyze_lockfile_diff(
            [],
            [],
            changed_lockfiles=(path,),
        )


def test_string_paths_rejected():
    with pytest.raises(LockfileDiffAnalysisError):
        analyze_lockfile_diff(
            [],
            [],
            changed_lockfiles="package-lock.json",
        )


def test_string_entries_rejected():
    with pytest.raises(LockfileDiffAnalysisError):
        analyze_lockfile_diff(
            "requests",
            [],
        )


def test_invalid_expected_change_prefix():
    with pytest.raises(LockfileDiffAnalysisError):
        analyze_lockfile_diff(
            [LockfileEntry("a", "1.0.0")],
            [LockfileEntry("a", "2.0.0")],
            changed_lockfiles=("package-lock.json",),
            expected_changes=("a changed",),
        )


def test_invalid_entry_type():
    with pytest.raises(LockfileDiffAnalysisError):
        analyze_lockfile_diff(
            [object()],
            [],
        )


def test_changed_lockfile_is_preserved():
    result = analyze_lockfile_diff(
        [],
        [LockfileEntry("a", "1.0.0")],
        changed_lockfiles=(
            "package-lock.json",
            "npm-shrinkwrap.json",
            "package-lock.json",
        ),
        expected_changes=("ADD:a:1.0.0",),
    )

    assert result.changed_lockfiles == (
        "npm-shrinkwrap.json",
        "package-lock.json",
    )


def test_serialization():
    result = analyze_lockfile_diff(
        [LockfileEntry("a", "1.0.0")],
        [LockfileEntry("a", "2.0.0")],
        changed_lockfiles=("package-lock.json",),
        expected_changes=("CHANGE:a:1.0.0->2.0.0",),
    )

    payload = result.to_json()
    data = json.loads(payload)

    assert data["state"] == "EXPECTED_CHANGE"
    assert data["valid"] is True
    assert data["is_safe"] is True


def test_validation():
    result = analyze_lockfile_diff(
        [],
        [],
    )

    assert validate_lockfile_diff_result(result)
    assert not validate_lockfile_diff_result(object())


def test_content_no_change():
    result = analyze_lockfile_content(
        '{"lockfileVersion": 3}',
        '{"lockfileVersion": 3}',
        lockfile_path="package-lock.json",
    )

    assert result.state is LockfileDiffState.NO_CHANGE
    assert result.valid


def test_content_change():
    result = analyze_lockfile_content(
        '{"lockfileVersion": 2}',
        '{"lockfileVersion": 3}',
        lockfile_path="package-lock.json",
        expected_changes=("CHANGE:__lockfile_hash__:package-lock.json:"
                          "OLD->NEW",),
    )

    assert result.changed_lockfiles == ("package-lock.json",)
    assert result.state is LockfileDiffState.UNEXPECTED_CHANGE


def test_invalid_content():
    with pytest.raises(LockfileDiffAnalysisError):
        analyze_lockfile_content(
            "",
            "{}",
            lockfile_path="package-lock.json",
        )


def test_entry_change_helpers():
    result = analyze_lockfile_diff(
        [LockfileEntry("a", "1.0.0")],
        [LockfileEntry("a", "2.0.0")],
        changed_lockfiles=("package-lock.json",),
        expected_changes=("CHANGE:a:1.0.0->2.0.0",),
    )

    change = result.changed_entries[0]

    assert not change.is_added
    assert not change.is_removed
    assert change.is_version_changed


def test_empty_scope_clean_repository():
    result = analyze_lockfile_diff([], [])

    assert result.state is LockfileDiffState.NO_CHANGE
    assert result.is_safe


def test_multiple_versions_are_compared():
    result = analyze_lockfile_diff(
        [
            LockfileEntry("pkg", "1.0.0"),
            LockfileEntry("pkg", "2.0.0"),
        ],
        [
            LockfileEntry("pkg", "1.0.0"),
            LockfileEntry("pkg", "3.0.0"),
        ],
        changed_lockfiles=("package-lock.json",),
        expected_changes=("CHANGE:pkg:1.0.0,2.0.0->1.0.0,3.0.0",),
    )

    assert result.state is LockfileDiffState.EXPECTED_CHANGE


def test_expected_addition_with_no_entry_change_is_not_false_positive():
    result = analyze_lockfile_diff(
        [LockfileEntry("a", "1.0.0")],
        [LockfileEntry("a", "1.0.0")],
        changed_lockfiles=("package-lock.json",),
        expected_changes=(),
    )

    assert result.state is LockfileDiffState.EXPECTED_CHANGE
    assert result.valid


def test_nonzero_content_hashes_are_deterministic():
    first = analyze_lockfile_content(
        '{"a":1}',
        '{"a":2}',
        lockfile_path="package-lock.json",
    )
    second = analyze_lockfile_content(
        '{"a":1}',
        '{"a":2}',
        lockfile_path="package-lock.json",
    )

    assert first.to_json() == second.to_json()
