import pytest

from sentinelshield.build_compatibility_assessment import (
    BuildCompatibilityInput,
    BuildCompatibilityResult,
    assess_build_compatibility,
    build_compatibility_assessment,
    check_build_compatibility,
    is_build_compatible,
)


def test_compatible_without_constraints():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "68.0.0",
    )

    assert result.compatible is True
    assert result.reason == "BUILD_COMPATIBLE"


def test_minimum_build_is_satisfied():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "68.0.0",
        minimum_build_version="65.0.0",
    )

    assert result.compatible is True


def test_build_below_minimum():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "64.0.0",
        minimum_build_version="65.0.0",
    )

    assert result.compatible is False
    assert result.reason == "BUILD_BELOW_MINIMUM"


def test_maximum_build_is_satisfied():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "68.0.0",
        maximum_build_version="70.0.0",
    )

    assert result.compatible is True


def test_build_above_maximum():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "71.0.0",
        maximum_build_version="70.0.0",
    )

    assert result.compatible is False
    assert result.reason == "BUILD_ABOVE_MAXIMUM"


def test_build_inside_range():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "68.0.0",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0",
    )

    assert result.compatible is True


def test_lower_boundary_is_inclusive():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "65.0.0",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0",
    )

    assert result.compatible is True


def test_upper_boundary_is_inclusive():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "70.0.0",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0",
    )

    assert result.compatible is True


def test_partial_versions_are_supported():
    result = assess_build_compatibility(
        "demo-package",
        "2.0",
        "setuptools",
        "68",
        minimum_build_version="65",
        maximum_build_version="70",
    )

    assert result.compatible is True


def test_version_prefix_and_suffix_are_supported():
    result = assess_build_compatibility(
        "demo-package",
        "v2.0.0+build",
        "setuptools",
        "v68.0.0-beta",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0+build",
    )

    assert result.compatible is True


def test_invalid_range_is_rejected():
    with pytest.raises(
        ValueError,
        match="MINIMUM_BUILD_EXCEEDS_MAXIMUM_BUILD",
    ):
        assess_build_compatibility(
            "demo-package",
            "2.0.0",
            "setuptools",
            "68.0.0",
            minimum_build_version="70.0.0",
            maximum_build_version="65.0.0",
        )


def test_invalid_build_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_build_compatibility(
            "demo-package",
            "2.0.0",
            "setuptools",
            "68.x.0",
        )


def test_invalid_candidate_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_build_compatibility(
            "demo-package",
            "2.x.0",
            "setuptools",
            "68.0.0",
        )


def test_candidate_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        assess_build_compatibility(
            "demo-package",
            200,
            "setuptools",
            "68.0.0",
        )


def test_build_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="BUILD_VERSION_MUST_BE_STRING",
    ):
        assess_build_compatibility(
            "demo-package",
            "2.0.0",
            "setuptools",
            680,
        )


def test_build_system_must_not_be_empty():
    with pytest.raises(
        ValueError,
        match="BUILD_SYSTEM_IS_EMPTY",
    ):
        assess_build_compatibility(
            "demo-package",
            "2.0.0",
            " ",
            "68.0.0",
        )


def test_optional_constraint_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="MINIMUM_BUILD_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        assess_build_compatibility(
            "demo-package",
            "2.0.0",
            "setuptools",
            "68.0.0",
            minimum_build_version=650,
        )


def test_none_package_name_is_allowed():
    result = assess_build_compatibility(
        None,
        "2.0.0",
        "setuptools",
        "68.0.0",
    )

    assert result.package_name is None
    assert result.compatible is True


def test_result_metadata():
    result = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "68.0.0",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0",
    )

    assert isinstance(result, BuildCompatibilityResult)
    assert result.package_name == "demo-package"
    assert result.candidate_version == "2.0.0"
    assert result.build_system == "setuptools"
    assert result.build_version == "68.0.0"
    assert result.minimum_build_version == "65.0.0"
    assert result.maximum_build_version == "70.0.0"
    assert result.compatible is True
    assert result.reason == "BUILD_COMPATIBLE"


def test_input_dataclass():
    value = BuildCompatibilityInput(
        package_name="demo-package",
        candidate_version="2.0.0",
        build_system="setuptools",
        build_version="68.0.0",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0",
    )

    assert value.package_name == "demo-package"
    assert value.candidate_version == "2.0.0"
    assert value.build_system == "setuptools"
    assert value.build_version == "68.0.0"


def test_public_aliases():
    assert build_compatibility_assessment is assess_build_compatibility
    assert check_build_compatibility is assess_build_compatibility
    assert is_build_compatible is assess_build_compatibility


def test_deterministic_result():
    first = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "68.0.0",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0",
    )

    second = assess_build_compatibility(
        "demo-package",
        "2.0.0",
        "setuptools",
        "68.0.0",
        minimum_build_version="65.0.0",
        maximum_build_version="70.0.0",
    )

    assert first == second
