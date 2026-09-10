import pytest

from sentinelshield.dependency_version_diff import (
    DependencyVersionDiffError,
    DependencyVersionDiffState,
    analyze_dependency_version_diff,
)


def test_no_change():
    result = analyze_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.31.0"},
    )

    assert result.state is DependencyVersionDiffState.NO_CHANGE
    assert result.changes == ()
    assert result.is_valid is True


def test_expected_change():
    result = analyze_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    assert result.state is DependencyVersionDiffState.EXPECTED_CHANGE
    assert len(result.expected_changes) == 1
    assert result.unexpected_changes == ()
    assert result.is_valid is True


def test_unexpected_version_change():
    result = analyze_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.33.0"},
        {"requests": "2.32.0"},
    )

    assert result.state is DependencyVersionDiffState.UNEXPECTED_CHANGE
    assert len(result.unexpected_changes) == 1
    assert result.is_valid is False


def test_unexpected_addition():
    result = analyze_dependency_version_diff(
        {"requests": "2.31.0"},
        {
            "requests": "2.31.0",
            "urllib3": "2.2.0",
        },
        {"requests": "2.31.0"},
    )

    assert result.state is DependencyVersionDiffState.UNEXPECTED_CHANGE
    assert result.unexpected_changes[0].name == "urllib3"


def test_unexpected_removal():
    result = analyze_dependency_version_diff(
        {
            "requests": "2.31.0",
            "urllib3": "2.2.0",
        },
        {"requests": "2.31.0"},
        {"requests": "2.31.0"},
    )

    assert result.state is DependencyVersionDiffState.UNEXPECTED_CHANGE
    assert result.unexpected_changes[0].name == "urllib3"


@pytest.mark.parametrize(
    "before,after",
    [
        (None, {}),
        ({}, None),
        ("invalid", {}),
        ({}, "invalid"),
    ],
)
def test_invalid_inventory(before, after):
    with pytest.raises(DependencyVersionDiffError):
        analyze_dependency_version_diff(before, after)


def test_empty_dependency_name_rejected():
    with pytest.raises(DependencyVersionDiffError):
        analyze_dependency_version_diff(
            {"": "1.0.0"},
            {"": "1.1.0"},
        )


def test_empty_version_rejected():
    with pytest.raises(DependencyVersionDiffError):
        analyze_dependency_version_diff(
            {"requests": ""},
            {"requests": "2.32.0"},
        )


def test_null_character_rejected():
    with pytest.raises(DependencyVersionDiffError):
        analyze_dependency_version_diff(
            {"requests": "2.31.0"},
            {"requests\\x00bad": "2.32.0"},
        )


def test_result_serialization():
    result = analyze_dependency_version_diff(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    data = result.to_dict()

    assert data["state"] == "EXPECTED_CHANGE"
    assert data["is_valid"] is True
    assert data["expected_changes"][0]["name"] == "requests"
