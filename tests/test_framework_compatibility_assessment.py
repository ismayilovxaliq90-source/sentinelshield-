import pytest

from sentinelshield.framework_compatibility_assessment import (
    FrameworkCompatibilityInput,
    FrameworkCompatibilityResult,
    assess_framework_compatibility,
    check_framework_compatibility,
    framework_compatibility_assessment,
    is_framework_compatible,
)


def test_compatible_without_constraints():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.2.0",
    )

    assert result.compatible is True
    assert result.reason == "FRAMEWORK_COMPATIBLE"


def test_minimum_framework_is_satisfied():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.2.0",
        minimum_framework_version="4.0.0",
    )

    assert result.compatible is True


def test_framework_below_minimum():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "3.2.0",
        minimum_framework_version="4.0.0",
    )

    assert result.compatible is False
    assert result.reason == "FRAMEWORK_BELOW_MINIMUM"


def test_maximum_framework_is_satisfied():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.2.0",
        maximum_framework_version="5.0.0",
    )

    assert result.compatible is True


def test_framework_above_maximum():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "5.1.0",
        maximum_framework_version="5.0.0",
    )

    assert result.compatible is False
    assert result.reason == "FRAMEWORK_ABOVE_MAXIMUM"


def test_framework_inside_range():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.2.0",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0",
    )

    assert result.compatible is True


def test_lower_boundary_is_inclusive():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.0.0",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0",
    )

    assert result.compatible is True


def test_upper_boundary_is_inclusive():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "5.0.0",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0",
    )

    assert result.compatible is True


def test_version_prefix_and_suffix_are_supported():
    result = assess_framework_compatibility(
        "demo-package",
        "v2.0.0+build",
        "django",
        "v4.2.0-beta",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0+build",
    )

    assert result.compatible is True


def test_partial_versions_are_supported():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0",
        "django",
        "4.2",
        minimum_framework_version="4.0",
        maximum_framework_version="5",
    )

    assert result.compatible is True


def test_invalid_range_is_rejected():
    with pytest.raises(
        ValueError,
        match="MINIMUM_FRAMEWORK_EXCEEDS_MAXIMUM_FRAMEWORK",
    ):
        assess_framework_compatibility(
            "demo-package",
            "2.0.0",
            "django",
            "4.2.0",
            minimum_framework_version="5.0.0",
            maximum_framework_version="4.0.0",
        )


def test_invalid_framework_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_framework_compatibility(
            "demo-package",
            "2.0.0",
            "django",
            "4.x.0",
        )


def test_invalid_candidate_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_framework_compatibility(
            "demo-package",
            "2.x.0",
            "django",
            "4.2.0",
        )


def test_candidate_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        assess_framework_compatibility(
            "demo-package",
            200,
            "django",
            "4.2.0",
        )


def test_framework_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="FRAMEWORK_VERSION_MUST_BE_STRING",
    ):
        assess_framework_compatibility(
            "demo-package",
            "2.0.0",
            "django",
            420,
        )


def test_framework_name_must_not_be_empty():
    with pytest.raises(
        ValueError,
        match="FRAMEWORK_NAME_IS_EMPTY",
    ):
        assess_framework_compatibility(
            "demo-package",
            "2.0.0",
            " ",
            "4.2.0",
        )


def test_optional_constraint_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="MINIMUM_FRAMEWORK_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        assess_framework_compatibility(
            "demo-package",
            "2.0.0",
            "django",
            "4.2.0",
            minimum_framework_version=400,
        )


def test_none_package_name_is_allowed():
    result = assess_framework_compatibility(
        None,
        "2.0.0",
        "django",
        "4.2.0",
    )

    assert result.package_name is None
    assert result.compatible is True


def test_result_metadata():
    result = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.2.0",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0",
    )

    assert isinstance(result, FrameworkCompatibilityResult)
    assert result.package_name == "demo-package"
    assert result.candidate_version == "2.0.0"
    assert result.framework_name == "django"
    assert result.framework_version == "4.2.0"
    assert result.minimum_framework_version == "4.0.0"
    assert result.maximum_framework_version == "5.0.0"
    assert result.compatible is True
    assert result.reason == "FRAMEWORK_COMPATIBLE"


def test_input_dataclass():
    value = FrameworkCompatibilityInput(
        package_name="demo-package",
        candidate_version="2.0.0",
        framework_name="django",
        framework_version="4.2.0",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0",
    )

    assert value.package_name == "demo-package"
    assert value.candidate_version == "2.0.0"
    assert value.framework_name == "django"
    assert value.framework_version == "4.2.0"


def test_public_aliases():
    assert framework_compatibility_assessment is assess_framework_compatibility
    assert check_framework_compatibility is assess_framework_compatibility
    assert is_framework_compatible is assess_framework_compatibility


def test_deterministic_result():
    first = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.2.0",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0",
    )

    second = assess_framework_compatibility(
        "demo-package",
        "2.0.0",
        "django",
        "4.2.0",
        minimum_framework_version="4.0.0",
        maximum_framework_version="5.0.0",
    )

    assert first == second
