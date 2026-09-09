import pytest

from sentinelshield.upgrade_path_generation import (
    UpgradePath,
    UpgradePathGenerationInput,
    UpgradePathGenerationResult,
    generate_upgrade_path,
    generate_upgrade_paths,
    upgrade_path_generation,
)


def test_generates_upgrade_paths():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["1.2.4", "1.3.0", "2.0.0"],
    )

    assert result.total == 3
    assert [p.target_version for p in result.paths] == [
        "1.2.4",
        "1.3.0",
        "2.0.0",
    ]


def test_path_starts_at_current_version():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["1.3.0"],
    )

    assert result.paths[0].versions == (
        "1.2.3",
        "1.3.0",
    )


def test_steps_are_calculated():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["1.4.5"],
    )

    path = result.paths[0]

    assert path.major_upgrades == 0
    assert path.minor_upgrades == 2
    assert path.patch_upgrades == 2
    assert path.steps == 4


def test_patch_distance():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["1.2.7"],
    )

    assert result.paths[0].upgrade_distance == 4


def test_minor_distance():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["1.4.3"],
    )

    assert result.paths[0].upgrade_distance == 2000


def test_major_distance():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["2.2.3"],
    )

    assert result.paths[0].upgrade_distance == 1_000_000


def test_non_upgrades_are_excluded():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["1.2.2", "1.2.3", "1.1.0"],
    )

    assert result.paths == ()
    assert result.total == 0


def test_duplicates_are_removed():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["1.2.4", "v1.2.4", "1.3.0"],
    )

    assert result.total == 2


def test_deterministic_ordering():
    result = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["2.0.0", "1.4.0", "1.2.5", "1.3.0"],
    )

    assert [p.target_version for p in result.paths] == [
        "1.2.5",
        "1.3.0",
        "1.4.0",
        "2.0.0",
    ]


def test_original_index_is_preserved():
    result = generate_upgrade_paths(
        "demo",
        "1.0.0",
        ["0.9.0", "1.2.0", "1.1.0"],
    )

    assert result.paths[0].original_index == 2
    assert result.paths[1].original_index == 1


def test_metadata_is_preserved():
    result = generate_upgrade_paths(
        "demo",
        "1.0.0",
        ["2.0.0"],
        vulnerability_id="CVE-TEST",
    )

    path = result.paths[0]

    assert path.package_name == "demo"
    assert path.current_version == "1.0.0"
    assert path.target_version == "2.0.0"


def test_partial_versions_are_supported():
    result = generate_upgrade_paths(
        "demo",
        "1.2",
        ["1.3"],
    )

    assert result.total == 1
    assert result.paths[0].target_version == "1.3"


def test_version_suffixes_are_supported():
    result = generate_upgrade_paths(
        "demo",
        "v1.2.3",
        ["1.2.4-beta", "1.3.0+build"],
    )

    assert result.total == 2


def test_empty_candidates():
    result = generate_upgrade_paths(
        "demo",
        "1.0.0",
        [],
    )

    assert result.paths == ()
    assert result.total == 0


def test_invalid_current_version():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        generate_upgrade_paths(
            "demo",
            "1.x.0",
            ["1.1.0"],
        )


def test_invalid_candidate_version():
    with pytest.raises(
        ValueError,
        match="VERSION_COMPONENTS_MUST_BE_NUMERIC",
    ):
        generate_upgrade_paths(
            "demo",
            "1.0.0",
            ["1.x.0"],
        )


def test_invalid_candidate_type():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSION_MUST_BE_STRING:0",
    ):
        generate_upgrade_paths(
            "demo",
            "1.0.0",
            [123],
        )


def test_invalid_package_name():
    with pytest.raises(
        TypeError,
        match="PACKAGE_NAME_MUST_BE_STRING",
    ):
        generate_upgrade_paths(
            123,
            "1.0.0",
            ["1.1.0"],
        )


def test_empty_package_name():
    with pytest.raises(
        ValueError,
        match="PACKAGE_NAME_IS_EMPTY",
    ):
        generate_upgrade_paths(
            " ",
            "1.0.0",
            ["1.1.0"],
        )


def test_candidate_collection_type():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_SEQUENCE",
    ):
        generate_upgrade_paths(
            "demo",
            "1.0.0",
            None,
        )


def test_string_candidate_collection():
    with pytest.raises(
        TypeError,
        match="CANDIDATE_VERSIONS_MUST_BE_SEQUENCE",
    ):
        generate_upgrade_paths(
            "demo",
            "1.0.0",
            "1.1.0",
        )


def test_result_dataclass():
    result = generate_upgrade_paths(
        "demo",
        "1.0.0",
        ["1.1.0"],
    )

    assert isinstance(result, UpgradePathGenerationResult)
    assert isinstance(result.paths[0], UpgradePath)


def test_input_dataclass():
    value = UpgradePathGenerationInput(
        package_name="demo",
        current_version="1.0.0",
        candidate_versions=["1.1.0"],
    )

    assert value.package_name == "demo"
    assert value.current_version == "1.0.0"
    assert value.candidate_versions == ["1.1.0"]


def test_public_aliases():
    assert (
        upgrade_path_generation
        is generate_upgrade_paths
    )
    assert (
        generate_upgrade_path
        is generate_upgrade_paths
    )


def test_deterministic_result():
    first = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["2.0.0", "1.3.0", "1.2.4"],
    )

    second = generate_upgrade_paths(
        "demo",
        "1.2.3",
        ["2.0.0", "1.3.0", "1.2.4"],
    )

    assert first == second


def test_input_is_not_modified():
    versions = ["2.0.0", "1.3.0", "1.2.4"]
    original = versions.copy()

    generate_upgrade_paths(
        "demo",
        "1.2.3",
        versions,
    )

    assert versions == original
