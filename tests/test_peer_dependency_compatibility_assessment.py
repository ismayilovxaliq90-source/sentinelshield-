import pytest

from sentinelshield.peer_dependency_compatibility_assessment import (
    PeerDependencyCompatibilityInput,
    PeerDependencyCompatibilityResult,
    assess_peer_dependency_compatibility,
    check_peer_dependency_compatibility,
    is_peer_dependency_compatible,
    peer_dependency_compatibility_assessment,
)


def test_compatible_without_constraints():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.2.0",
    )

    assert result.compatible is True
    assert result.reason == "PEER_DEPENDENCY_COMPATIBLE"


def test_minimum_peer_version_is_satisfied():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.2.0",
        minimum_peer_version="4.0.0",
    )

    assert result.compatible is True


def test_peer_below_minimum():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "3.9.0",
        minimum_peer_version="4.0.0",
    )

    assert result.compatible is False
    assert result.reason == "PEER_BELOW_MINIMUM"


def test_maximum_peer_version_is_satisfied():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.2.0",
        maximum_peer_version="5.0.0",
    )

    assert result.compatible is True


def test_peer_above_maximum():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "5.1.0",
        maximum_peer_version="5.0.0",
    )

    assert result.compatible is False
    assert result.reason == "PEER_ABOVE_MAXIMUM"


def test_peer_inside_range():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.2.0",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0",
    )

    assert result.compatible is True


def test_lower_boundary_is_inclusive():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.0.0",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0",
    )

    assert result.compatible is True


def test_upper_boundary_is_inclusive():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "5.0.0",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0",
    )

    assert result.compatible is True


def test_partial_versions_are_supported():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0",
        "framework",
        "4.2",
        minimum_peer_version="4",
        maximum_peer_version="5",
    )

    assert result.compatible is True


def test_version_prefix_and_suffix_are_supported():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "v2.0.0+build",
        "framework",
        "v4.2.0-beta",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0+build",
    )

    assert result.compatible is True


def test_invalid_range_is_rejected():
    with pytest.raises(
        ValueError,
        match="MINIMUM_PEER_EXCEEDS_MAXIMUM_PEER",
    ):
        assess_peer_dependency_compatibility(
            "demo-package",
            "2.0.0",
            "framework",
            "4.2.0",
            minimum_peer_version="5.0.0",
            maximum_peer_version="4.0.0",
        )


def test_invalid_peer_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_peer_dependency_compatibility(
            "demo-package",
            "2.0.0",
            "framework",
            "4.x.0",
        )


def test_invalid_candidate_version_is_rejected():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        assess_peer_dependency_compatibility(
            "demo-package",
            "2.x.0",
            "framework",
            "4.2.0",
        )


def test_candidate_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING",
    ):
        assess_peer_dependency_compatibility(
            "demo-package",
            200,
            "framework",
            "4.2.0",
        )


def test_peer_version_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="PEER_VERSION_MUST_BE_STRING",
    ):
        assess_peer_dependency_compatibility(
            "demo-package",
            "2.0.0",
            "framework",
            420,
        )


def test_peer_dependency_name_must_not_be_empty():
    with pytest.raises(
        ValueError,
        match="PEER_DEPENDENCY_NAME_IS_EMPTY",
    ):
        assess_peer_dependency_compatibility(
            "demo-package",
            "2.0.0",
            " ",
            "4.2.0",
        )


def test_optional_constraint_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="MINIMUM_PEER_VERSION_MUST_BE_STRING_OR_NONE",
    ):
        assess_peer_dependency_compatibility(
            "demo-package",
            "2.0.0",
            "framework",
            "4.2.0",
            minimum_peer_version=400,
        )


def test_none_package_name_is_allowed():
    result = assess_peer_dependency_compatibility(
        None,
        "2.0.0",
        "framework",
        "4.2.0",
    )

    assert result.package_name is None
    assert result.compatible is True


def test_result_metadata():
    result = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.2.0",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0",
    )

    assert isinstance(result, PeerDependencyCompatibilityResult)
    assert result.package_name == "demo-package"
    assert result.candidate_version == "2.0.0"
    assert result.peer_dependency_name == "framework"
    assert result.peer_version == "4.2.0"
    assert result.minimum_peer_version == "4.0.0"
    assert result.maximum_peer_version == "5.0.0"
    assert result.compatible is True
    assert result.reason == "PEER_DEPENDENCY_COMPATIBLE"


def test_input_dataclass():
    value = PeerDependencyCompatibilityInput(
        package_name="demo-package",
        candidate_version="2.0.0",
        peer_dependency_name="framework",
        peer_version="4.2.0",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0",
    )

    assert value.package_name == "demo-package"
    assert value.candidate_version == "2.0.0"
    assert value.peer_dependency_name == "framework"
    assert value.peer_version == "4.2.0"


def test_public_aliases():
    assert (
        peer_dependency_compatibility_assessment
        is assess_peer_dependency_compatibility
    )
    assert (
        check_peer_dependency_compatibility
        is assess_peer_dependency_compatibility
    )
    assert (
        is_peer_dependency_compatible
        is assess_peer_dependency_compatibility
    )


def test_deterministic_result():
    first = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.2.0",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0",
    )

    second = assess_peer_dependency_compatibility(
        "demo-package",
        "2.0.0",
        "framework",
        "4.2.0",
        minimum_peer_version="4.0.0",
        maximum_peer_version="5.0.0",
    )

    assert first == second
