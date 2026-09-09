import pytest

from sentinelshield.lockfile_compatibility_assessment import (
    LockfileCompatibilityInput,
    LockfileCompatibilityResult,
    assess_lockfile_compatibility,
    check_lockfile_compatibility,
    is_lockfile_compatible,
    lockfile_compatibility_assessment,
)


def test_exact_locked_version_is_compatible():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        "2.0.0",
    )

    assert result.compatible is True
    assert result.reason == "LOCKFILE_COMPATIBLE"


def test_candidate_different_from_lockfile_is_incompatible():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.1.0",
        "2.0.0",
    )

    assert result.compatible is False
    assert result.reason == "CANDIDATE_DIFFERS_FROM_LOCKFILE"


def test_required_version_matching_candidate_and_lockfile():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        "2.0.0",
        required_version="2.0.0",
    )

    assert result.compatible is True


def test_candidate_must_match_required_version():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.1.0",
        "2.0.0",
        required_version="2.0.0",
    )

    assert result.compatible is False
    assert result.reason == "CANDIDATE_DOES_NOT_MATCH_REQUIRED_VERSION"


def test_lockfile_must_match_required_version():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        "2.1.0",
        required_version="2.0.0",
    )

    assert result.compatible is False
    assert result.reason == "LOCKFILE_DOES_NOT_MATCH_REQUIRED_VERSION"


def test_no_lockfile_version_is_compatible_without_requirement():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        None,
    )

    assert result.compatible is True
    assert result.reason == "NO_LOCKED_VERSION"


def test_no_lockfile_version_with_matching_requirement():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        None,
        required_version="2.0.0",
    )

    assert result.compatible is True
    assert result.reason == "NO_LOCKED_VERSION"


def test_no_lockfile_version_with_nonmatching_requirement():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.1.0",
        None,
        required_version="2.0.0",
    )

    assert result.compatible is False
    assert result.reason == "CANDIDATE_DOES_NOT_MATCH_REQUIRED_VERSION"


def test_partial_versions_are_supported():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2",
        "2.0.0",
    )

    assert result.compatible is True


def test_version_prefix_and_suffix_are_supported():
    result = assess_lockfile_compatibility(
        "demo-package",
        "v2.0.0+build",
        "2.0.0-beta",
    )

    assert result.compatible is True


def test_invalid_candidate_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            "2.x.0",
            "2.0.0",
        )


def test_invalid_lockfile_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            "2.0.0",
            "2.x.0",
        )


def test_invalid_required_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            "2.0.0",
            "2.0.0",
            required_version="x.0.0",
        )


def test_candidate_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            200,
            "2.0.0",
        )


def test_lockfile_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="LOCKFILE_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            "2.0.0",
            200,
        )


def test_required_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="REQUIRED_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            "2.0.0",
            "2.0.0",
            required_version=200,
        )


def test_empty_lockfile_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="LOCKFILE_VERSION_IS_EMPTY",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            "2.0.0",
            " ",
        )


def test_empty_required_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="REQUIRED_VERSION_IS_EMPTY",
    ):
        assess_lockfile_compatibility(
            "demo-package",
            "2.0.0",
            "2.0.0",
            required_version=" ",
        )


def test_none_package_name_is_allowed():
    result = assess_lockfile_compatibility(
        None,
        "2.0.0",
        "2.0.0",
    )

    assert result.package_name is None
    assert result.compatible is True


def test_result_metadata():
    result = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        "2.0.0",
        required_version="2.0.0",
    )

    assert isinstance(result, LockfileCompatibilityResult)
    assert result.package_name == "demo-package"
    assert result.candidate_version == "2.0.0"
    assert result.lockfile_version == "2.0.0"
    assert result.required_version == "2.0.0"
    assert result.compatible is True
    assert result.reason == "LOCKFILE_COMPATIBLE"


def test_input_dataclass():
    value = LockfileCompatibilityInput(
        package_name="demo-package",
        candidate_version="2.0.0",
        lockfile_version="2.0.0",
        required_version="2.0.0",
    )

    assert value.package_name == "demo-package"
    assert value.candidate_version == "2.0.0"
    assert value.lockfile_version == "2.0.0"
    assert value.required_version == "2.0.0"


def test_public_aliases():
    assert lockfile_compatibility_assessment is assess_lockfile_compatibility
    assert check_lockfile_compatibility is assess_lockfile_compatibility
    assert is_lockfile_compatible is assess_lockfile_compatibility


def test_deterministic_result():
    first = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        "2.0.0",
        required_version="2.0.0",
    )

    second = assess_lockfile_compatibility(
        "demo-package",
        "2.0.0",
        "2.0.0",
        required_version="2.0.0",
    )

    assert first == second
