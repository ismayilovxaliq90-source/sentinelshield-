import pytest

from sentinelshield.version_constraint_compatibility_check import (
    VersionConstraintCompatibilityResult,
    VersionConstraintCheckInput,
    check_version_constraint_compatibility,
    is_version_constraint_compatible,
    version_constraint_compatibility_check,
)


def test_exact_version_matches():
    result = check_version_constraint_compatibility(
        "1.2.3",
        "==1.2.3",
    )

    assert result.compatible is True
    assert result.reason == "VERSION_SATISFIES_CONSTRAINT"


def test_exact_version_mismatch():
    result = check_version_constraint_compatibility(
        "1.2.4",
        "==1.2.3",
    )

    assert result.compatible is False
    assert result.reason == "VERSION_DOES_NOT_SATISFY_CONSTRAINT"


def test_bare_version_means_exact_match():
    assert check_version_constraint_compatibility(
        "1.2.3",
        "1.2.3",
    ).compatible is True


def test_greater_than():
    assert check_version_constraint_compatibility(
        "1.3.0",
        ">1.2.3",
    ).compatible is True

    assert check_version_constraint_compatibility(
        "1.2.3",
        ">1.2.3",
    ).compatible is False


def test_greater_than_or_equal():
    assert check_version_constraint_compatibility(
        "1.2.3",
        ">=1.2.3",
    ).compatible is True

    assert check_version_constraint_compatibility(
        "1.2.2",
        ">=1.2.3",
    ).compatible is False


def test_less_than():
    assert check_version_constraint_compatibility(
        "1.2.2",
        "<1.2.3",
    ).compatible is True

    assert check_version_constraint_compatibility(
        "1.2.3",
        "<1.2.3",
    ).compatible is False


def test_less_than_or_equal():
    assert check_version_constraint_compatibility(
        "1.2.3",
        "<=1.2.3",
    ).compatible is True

    assert check_version_constraint_compatibility(
        "1.2.4",
        "<=1.2.3",
    ).compatible is False


def test_not_equal():
    assert check_version_constraint_compatibility(
        "1.2.4",
        "!=1.2.3",
    ).compatible is True

    assert check_version_constraint_compatibility(
        "1.2.3",
        "!=1.2.3",
    ).compatible is False


def test_equals_operator_is_supported():
    assert check_version_constraint_compatibility(
        "1.2.3",
        "=1.2.3",
    ).compatible is True


def test_range_with_comma():
    result = check_version_constraint_compatibility(
        "1.5.0",
        ">=1.2.0,<2.0.0",
    )

    assert result.compatible is True


def test_range_with_spaces():
    result = check_version_constraint_compatibility(
        "1.5.0",
        ">=1.2.0 <2.0.0",
    )

    assert result.compatible is True


def test_range_lower_boundary():
    assert check_version_constraint_compatibility(
        "1.2.0",
        ">=1.2.0 <2.0.0",
    ).compatible is True


def test_range_upper_boundary():
    assert check_version_constraint_compatibility(
        "2.0.0",
        ">=1.2.0 <2.0.0",
    ).compatible is False


def test_range_rejects_below_lower_bound():
    assert check_version_constraint_compatibility(
        "1.1.9",
        ">=1.2.0 <2.0.0",
    ).compatible is False


def test_v_prefix_is_supported():
    result = check_version_constraint_compatibility(
        "v1.2.3",
        ">=1.2.0",
    )

    assert result.compatible is True


def test_suffixes_are_ignored_for_numeric_compatibility():
    result = check_version_constraint_compatibility(
        "1.3.0-alpha",
        ">=1.2.0",
    )

    assert result.compatible is True


def test_result_metadata():
    result = check_version_constraint_compatibility(
        "1.3.0",
        ">=1.2.0",
    )

    assert isinstance(result, VersionConstraintCompatibilityResult)
    assert result.version == "1.3.0"
    assert result.constraint == ">=1.2.0"
    assert result.compatible is True


def test_input_dataclass_exists():
    value = VersionConstraintCheckInput(
        version="1.2.3",
        constraint=">=1.0.0",
    )

    assert value.version == "1.2.3"
    assert value.constraint == ">=1.0.0"


def test_whitespace_is_normalized():
    result = check_version_constraint_compatibility(
        "  1.2.3  ",
        "  >=1.2.0  ",
    )

    assert result.version == "1.2.3"
    assert result.constraint == ">=1.2.0"
    assert result.compatible is True


def test_none_version_rejected():
    with pytest.raises(TypeError, match="VERSION_MUST_BE_STRING"):
        check_version_constraint_compatibility(None, ">=1.0.0")


def test_none_constraint_rejected():
    with pytest.raises(TypeError, match="CONSTRAINT_MUST_BE_STRING"):
        check_version_constraint_compatibility("1.2.3", None)


def test_empty_version_rejected():
    with pytest.raises(ValueError, match="VERSION_IS_EMPTY"):
        check_version_constraint_compatibility("", ">=1.0.0")


def test_empty_constraint_rejected():
    with pytest.raises(ValueError, match="CONSTRAINT_IS_EMPTY"):
        check_version_constraint_compatibility("1.2.3", "")


def test_invalid_version_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_MUST_HAVE_MAJOR_MINOR_PATCH",
    ):
        check_version_constraint_compatibility(
            "1.2",
            ">=1.0.0",
        )


def test_invalid_constraint_version_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_MUST_HAVE_MAJOR_MINOR_PATCH",
    ):
        check_version_constraint_compatibility(
            "1.2.3",
            ">=1.2",
        )


def test_unsupported_operator_rejected():
    with pytest.raises(ValueError, match="UNSUPPORTED_CONSTRAINT_OPERATOR"):
        check_version_constraint_compatibility(
            "1.2.3",
            "~1.2.3",
        )


def test_public_aliases():
    assert (
        version_constraint_compatibility_check
        is check_version_constraint_compatibility
    )
    assert (
        is_version_constraint_compatible
        is check_version_constraint_compatibility
    )


def test_deterministic_result():
    first = check_version_constraint_compatibility(
        "1.5.0",
        ">=1.2.0 <2.0.0",
    )

    second = check_version_constraint_compatibility(
        "1.5.0",
        ">=1.2.0 <2.0.0",
    )

    assert first == second
