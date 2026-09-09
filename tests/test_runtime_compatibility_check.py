import pytest

from sentinelshield.runtime_compatibility_check import (
    RuntimeCompatibilityInput,
    RuntimeCompatibilityResult,
    check_runtime_compatibility,
    is_runtime_compatible,
    runtime_compatibility_check,
)


def test_runtime_is_compatible_without_constraints():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.0",
    )

    assert result.compatible is True
    assert result.reason == "RUNTIME_COMPATIBLE"


def test_runtime_meets_minimum():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.0",
        minimum_runtime_version="3.10.0",
    )

    assert result.compatible is True


def test_runtime_below_minimum():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.9.0",
        minimum_runtime_version="3.10.0",
    )

    assert result.compatible is False
    assert result.reason == "RUNTIME_BELOW_MINIMUM"


def test_runtime_meets_maximum():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.0",
        maximum_runtime_version="3.12.0",
    )

    assert result.compatible is True


def test_runtime_above_maximum():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.13.0",
        maximum_runtime_version="3.12.0",
    )

    assert result.compatible is False
    assert result.reason == "RUNTIME_ABOVE_MAXIMUM"


def test_runtime_inside_range():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.5",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    assert result.compatible is True


def test_runtime_at_lower_boundary():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.10.0",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    assert result.compatible is True


def test_runtime_at_upper_boundary():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.12.0",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    assert result.compatible is True


def test_runtime_outside_both_sides():
    below = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.9.9",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    above = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.13.0",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    assert below.compatible is False
    assert below.reason == "RUNTIME_BELOW_MINIMUM"

    assert above.compatible is False
    assert above.reason == "RUNTIME_ABOVE_MAXIMUM"


def test_partial_runtime_version_is_supported():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11",
        minimum_runtime_version="3.10",
        maximum_runtime_version="3.12",
    )

    assert result.compatible is True
    assert result.runtime_version == "3.11"


def test_v_prefix_is_supported():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "v3.11.0",
        minimum_runtime_version="v3.10.0",
    )

    assert result.compatible is True


def test_suffixes_are_supported():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.0",
        minimum_runtime_version="3.10.0-alpha",
        maximum_runtime_version="3.12.0+build",
    )

    assert result.compatible is True


def test_invalid_constraint_range_is_rejected():
    with pytest.raises(
        ValueError,
        match="MINIMUM_RUNTIME_EXCEEDS_MAXIMUM_RUNTIME",
    ):
        check_runtime_compatibility(
            "pkg",
            "2.0.0",
            "3.11.0",
            minimum_runtime_version="3.12.0",
            maximum_runtime_version="3.10.0",
        )


def test_result_metadata():
    result = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.0",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    assert isinstance(result, RuntimeCompatibilityResult)
    assert result.package_name == "pkg"
    assert result.candidate_version == "2.0.0"
    assert result.runtime_version == "3.11.0"
    assert result.minimum_runtime_version == "3.10.0"
    assert result.maximum_runtime_version == "3.12.0"
    assert result.compatible is True
    assert result.reason == "RUNTIME_COMPATIBLE"


def test_input_dataclass():
    value = RuntimeCompatibilityInput(
        package_name="pkg",
        candidate_version="2.0.0",
        runtime_version="3.11.0",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    assert value.package_name == "pkg"
    assert value.candidate_version == "2.0.0"
    assert value.runtime_version == "3.11.0"


def test_none_package_name_is_allowed():
    result = check_runtime_compatibility(
        None,
        "2.0.0",
        "3.11.0",
    )

    assert result.compatible is True
    assert result.package_name is None


def test_invalid_candidate_type():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        check_runtime_compatibility(
            "pkg",
            2,
            "3.11.0",
        )


def test_invalid_runtime_type():
    with pytest.raises(
        TypeError,
        match="RUNTIME_VERSION_MUST_BE_STRING",
    ):
        check_runtime_compatibility(
            "pkg",
            "2.0.0",
            311,
        )


def test_invalid_minimum_type():
    with pytest.raises(
        TypeError,
        match="MINIMUM_RUNTIME_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        check_runtime_compatibility(
            "pkg",
            "2.0.0",
            "3.11.0",
            minimum_runtime_version=310,
        )


def test_invalid_maximum_type():
    with pytest.raises(
        TypeError,
        match="MAXIMUM_RUNTIME_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        check_runtime_compatibility(
            "pkg",
            "2.0.0",
            "3.11.0",
            maximum_runtime_version=312,
        )


def test_empty_runtime_version():
    with pytest.raises(ValueError, match="VERSION_IS_EMPTY"):
        check_runtime_compatibility(
            "pkg",
            "2.0.0",
            "",
        )


def test_invalid_runtime_version():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        check_runtime_compatibility(
            "pkg",
            "2.0.0",
            "3.x.0",
        )


def test_public_aliases():
    assert runtime_compatibility_check is check_runtime_compatibility
    assert is_runtime_compatible is check_runtime_compatibility


def test_deterministic_result():
    first = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.0",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    second = check_runtime_compatibility(
        "pkg",
        "2.0.0",
        "3.11.0",
        minimum_runtime_version="3.10.0",
        maximum_runtime_version="3.12.0",
    )

    assert first == second
