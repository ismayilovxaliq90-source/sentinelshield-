import pytest

from sentinelshield.dependency_version_diff import (
    DependencyVersionDiffError,
    DependencyVersionDiffState,
    compare_dependency_versions,
)


def test_no_change():
    result = compare_dependency_versions(
        {"requests": "2.31.0"},
        {"requests": "2.31.0"},
    )

    assert result.state is DependencyVersionDiffState.NO_CHANGE
    assert result.changes == ()
    assert result.is_valid is True


def test_expected_change():
    result = compare_dependency_versions(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    assert result.state is DependencyVersionDiffState.EXPECTED_CHANGE
    assert len(result.expected_changes) == 1
    assert result.unexpected_changes == ()
    assert result.is_valid is True


def test_unexpected_version_change():
    result = compare_dependency_versions(
        {"requests": "2.31.0"},
        {"requests": "2.33.0"},
        {"requests": "2.32.0"},
    )

    assert result.state is DependencyVersionDiffState.UNEXPECTED_CHANGE
    assert len(result.unexpected_changes) == 1
    assert result.is_valid is False


def test_unexpected_addition():
    result = compare_dependency_versions(
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
    result = compare_dependency_versions(
        {
            "requests": "2.31.0",
            "urllib3": "2.2.0",
        },
        {"requests": "2.31.0"},
        {"requests": "2.31.0"},
    )

    assert result.state is DependencyVersionDiffState.UNEXPECTED_CHANGE
    assert result.unexpected_changes[0].name == "urllib3"


def test_multiple_expected_changes():
    result = compare_dependency_versions(
        {
            "requests": "2.31.0",
            "urllib3": "2.1.0",
        },
        {
            "requests": "2.32.0",
            "urllib3": "2.2.0",
        },
        {
            "requests": "2.32.0",
            "urllib3": "2.2.0",
        },
    )

    assert result.state is DependencyVersionDiffState.EXPECTED_CHANGE
    assert len(result.expected_changes) == 2
    assert result.unexpected_changes == ()


def test_mixed_expected_and_unexpected_changes():
    result = compare_dependency_versions(
        {
            "requests": "2.31.0",
            "urllib3": "2.1.0",
        },
        {
            "requests": "2.32.0",
            "urllib3": "2.3.0",
        },
        {
            "requests": "2.32.0",
            "urllib3": "2.2.0",
        },
    )

    assert result.state is DependencyVersionDiffState.UNEXPECTED_CHANGE
    assert len(result.expected_changes) == 1
    assert len(result.unexpected_changes) == 1


def test_empty_dependency_name_rejected():
    with pytest.raises(DependencyVersionDiffError):
        compare_dependency_versions(
            {"": "1.0.0"},
            {"": "2.0.0"},
        )


def test_empty_version_rejected():
    with pytest.raises(DependencyVersionDiffError):
        compare_dependency_versions(
            {"requests": ""},
            {"requests": "2.0.0"},
        )


def test_null_dependency_name_rejected():
    with pytest.raises(DependencyVersionDiffError):
        compare_dependency_versions(
            {"requests\x00bad": "1.0.0"},
            {"requests\x00bad": "2.0.0"},
        )


def test_null_version_rejected():
    with pytest.raises(DependencyVersionDiffError):
        compare_dependency_versions(
            {"requests": "1.0.0"},
            {"requests": "2.0.0\x00bad"},
        )


def test_invalid_before_input_rejected():
    with pytest.raises(DependencyVersionDiffError):
        compare_dependency_versions(
            None,
            {},
        )


def test_invalid_after_input_rejected():
    with pytest.raises(DependencyVersionDiffError):
        compare_dependency_versions(
            {},
            None,
        )


def test_result_serialization():
    result = compare_dependency_versions(
        {"requests": "2.31.0"},
        {"requests": "2.32.0"},
        {"requests": "2.32.0"},
    )

    data = result.to_dict()

    assert data["state"] == "EXPECTED_CHANGE"
    assert data["has_changes"] is True
    assert data["is_valid"] is True
    assert data["changes"][0]["name"] == "requests"
