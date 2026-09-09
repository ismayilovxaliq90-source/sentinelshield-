import pytest

from sentinelshield.api_compatibility_assessment import (
    APICompatibilityInput,
    APICompatibilityResult,
    assess_api_compatibility,
    api_compatibility_assessment,
    check_api_compatibility,
    is_api_compatible,
)


def test_compatible_without_constraints():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.0.0",
    )

    assert result.compatible is True
    assert result.reason == "API_COMPATIBLE"


def test_minimum_api_is_satisfied():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.5.0",
        minimum_api_version="2.0.0",
    )

    assert result.compatible is True


def test_api_below_minimum():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "1.9.0",
        minimum_api_version="2.0.0",
    )

    assert result.compatible is False
    assert result.reason == "API_BELOW_MINIMUM"


def test_maximum_api_is_satisfied():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.5.0",
        maximum_api_version="3.0.0",
    )

    assert result.compatible is True


def test_api_above_maximum():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "3.1.0",
        maximum_api_version="3.0.0",
    )

    assert result.compatible is False
    assert result.reason == "API_ABOVE_MAXIMUM"


def test_api_inside_range():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.5.0",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0",
    )

    assert result.compatible is True


def test_lower_boundary_is_inclusive():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.0.0",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0",
    )

    assert result.compatible is True


def test_upper_boundary_is_inclusive():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "3.0.0",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0",
    )

    assert result.compatible is True


def test_partial_versions_are_supported():
    result = assess_api_compatibility(
        "demo-package",
        "2.0",
        "demo-api",
        "2.5",
        minimum_api_version="2",
        maximum_api_version="3",
    )

    assert result.compatible is True


def test_version_prefix_and_suffix_are_supported():
    result = assess_api_compatibility(
        "demo-package",
        "v2.0.0+build",
        "demo-api",
        "v2.5.0-beta",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0+build",
    )

    assert result.compatible is True


def test_invalid_range_is_rejected():
    with pytest.raises(
        ValueError,
        match="MINIMUM_API_EXCEEDS_MAXIMUM_API",
    ):
        assess_api_compatibility(
            "demo-package",
            "2.0.0",
            "demo-api",
            "2.5.0",
            minimum_api_version="4.0.0",
            maximum_api_version="3.0.0",
        )


def test_invalid_api_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_api_compatibility(
            "demo-package",
            "2.0.0",
            "demo-api",
            "2.x.0",
        )


def test_invalid_candidate_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_api_compatibility(
            "demo-package",
            "x.0.0",
            "demo-api",
            "2.0.0",
        )


def test_candidate_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        assess_api_compatibility(
            "demo-package",
            200,
            "demo-api",
            "2.0.0",
        )


def test_api_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="API_VERSION_MUST_BE_STRING",
    ):
        assess_api_compatibility(
            "demo-package",
            "2.0.0",
            "demo-api",
            200,
        )


def test_api_name_must_not_be_empty():
    with pytest.raises(
        ValueError,
        match="API_NAME_IS_EMPTY",
    ):
        assess_api_compatibility(
            "demo-package",
            "2.0.0",
            " ",
            "2.0.0",
        )


def test_optional_constraint_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="MINIMUM_API_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        assess_api_compatibility(
            "demo-package",
            "2.0.0",
            "demo-api",
            "2.0.0",
            minimum_api_version=200,
        )


def test_none_package_name_is_allowed():
    result = assess_api_compatibility(
        None,
        "2.0.0",
        "demo-api",
        "2.0.0",
    )

    assert result.package_name is None
    assert result.compatible is True


def test_result_metadata():
    result = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.5.0",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0",
    )

    assert isinstance(result, APICompatibilityResult)
    assert result.package_name == "demo-package"
    assert result.candidate_version == "2.0.0"
    assert result.api_name == "demo-api"
    assert result.api_version == "2.5.0"
    assert result.minimum_api_version == "2.0.0"
    assert result.maximum_api_version == "3.0.0"
    assert result.compatible is True
    assert result.reason == "API_COMPATIBLE"


def test_input_dataclass():
    value = APICompatibilityInput(
        package_name="demo-package",
        candidate_version="2.0.0",
        api_name="demo-api",
        api_version="2.5.0",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0",
    )

    assert value.package_name == "demo-package"
    assert value.candidate_version == "2.0.0"
    assert value.api_name == "demo-api"
    assert value.api_version == "2.5.0"


def test_public_aliases():
    assert api_compatibility_assessment is assess_api_compatibility
    assert check_api_compatibility is assess_api_compatibility
    assert is_api_compatible is assess_api_compatibility


def test_deterministic_result():
    first = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.5.0",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0",
    )

    second = assess_api_compatibility(
        "demo-package",
        "2.0.0",
        "demo-api",
        "2.5.0",
        minimum_api_version="2.0.0",
        maximum_api_version="3.0.0",
    )

    assert first == second
