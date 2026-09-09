import pytest

from sentinelshield.patch_version_candidate_detection import (
    PatchVersionCandidate,
    PatchVersionCandidateDetectionResult,
    PatchVersionDetectionInput,
    detect_patch_version_candidates,
    patch_version_candidate_detection,
)


def item(
    vulnerability_id,
    package_name,
    current_version,
    fixed_versions,
    source="OSV",
):
    return {
        "vulnerability_id": vulnerability_id,
        "package_name": package_name,
        "current_version": current_version,
        "fixed_versions": fixed_versions,
        "source": source,
    }


def test_empty_input():
    result = detect_patch_version_candidates([])

    assert result.candidates == ()
    assert result.total == 0
    assert result.vulnerabilities_processed == 0


def test_patch_version_is_detected():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "requests",
                "2.31.0",
                ["2.31.1"],
            )
        ]
    )

    assert result.total == 1

    candidate = result.candidates[0]

    assert candidate.vulnerability_id == "CVE-1"
    assert candidate.package_name == "requests"
    assert candidate.current_version == "2.31.0"
    assert candidate.fixed_version == "2.31.1"
    assert candidate.patch_distance == 1
    assert candidate.source == "OSV"


def test_multiple_patch_versions():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.2.4", "1.2.5", "1.2.10"],
            )
        ]
    )

    assert [
        x.fixed_version
        for x in result.candidates
    ] == [
        "1.2.4",
        "1.2.5",
        "1.2.10",
    ]


def test_minor_upgrade_is_not_patch():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.3.0"],
            )
        ]
    )

    assert result.total == 0


def test_major_upgrade_is_not_patch():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["2.0.0"],
            )
        ]
    )

    assert result.total == 0


def test_equal_version_is_not_patch():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.2.3"],
            )
        ]
    )

    assert result.total == 0


def test_older_patch_is_not_candidate():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.2.2"],
            )
        ]
    )

    assert result.total == 0


def test_duplicate_patch_versions_removed():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.2.4", "1.2.4", "1.2.5"],
            )
        ]
    )

    assert [
        x.fixed_version
        for x in result.candidates
    ] == ["1.2.4", "1.2.5"]


def test_mixed_candidates_only_patch_versions_remain():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                [
                    "1.2.4",
                    "1.3.0",
                    "2.0.0",
                    "1.2.2",
                    "1.2.10",
                ],
            )
        ]
    )

    assert [
        x.fixed_version
        for x in result.candidates
    ] == ["1.2.4", "1.2.10"]


def test_patch_distance_is_correct():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.2.8"],
            )
        ]
    )

    assert result.candidates[0].patch_distance == 5


def test_version_numeric_order_is_correct():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.2.10", "1.2.4", "1.2.5"],
            )
        ]
    )

    assert [
        x.fixed_version
        for x in result.candidates
    ] == [
        "1.2.4",
        "1.2.5",
        "1.2.10",
    ]


def test_v_prefix_is_supported():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "v1.2.3",
                ["v1.2.4"],
            )
        ]
    )

    assert result.total == 1


def test_release_metadata_does_not_change_patch_class():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.3",
                ["1.2.4+build1"],
            )
        ]
    )

    assert result.total == 1


def test_multiple_vulnerabilities():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg-a",
                "1.0.0",
                ["1.0.1"],
            ),
            item(
                "CVE-2",
                "pkg-b",
                "2.3.4",
                ["2.3.5", "2.4.0"],
            ),
        ]
    )

    assert result.total == 2
    assert result.vulnerabilities_processed == 2


def test_input_order_preserved():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-A",
                "a",
                "1.0.0",
                ["1.0.1"],
            ),
            item(
                "CVE-B",
                "b",
                "1.0.0",
                ["1.0.1"],
            ),
        ]
    )

    assert [
        x.vulnerability_id
        for x in result.candidates
    ] == ["CVE-A", "CVE-B"]


def test_dataclass_input():
    data = PatchVersionDetectionInput(
        vulnerability_id="CVE-DATA",
        package_name="urllib3",
        current_version="1.26.17",
        fixed_versions=("1.26.18",),
        source="GHSA",
    )

    result = detect_patch_version_candidates([data])

    assert result.total == 1
    assert result.candidates[0].fixed_version == "1.26.18"


def test_mapping_input():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-MAP",
                "flask",
                "2.3.1",
                ["2.3.2"],
            )
        ]
    )

    assert result.total == 1


def test_input_not_mutated():
    source = [
        item(
            "CVE-1",
            "pkg",
            "1.2.3",
            ["1.2.4", "1.3.0"],
        )
    ]

    original = {
        key: (
            list(value)
            if key == "fixed_versions"
            else value
        )
        for key, value in source[0].items()
    }

    detect_patch_version_candidates(source)

    assert source[0] == original


def test_deterministic_result():
    source = [
        item(
            "CVE-1",
            "pkg",
            "1.2.3",
            ["1.2.5", "1.2.4"],
        )
    ]

    first = detect_patch_version_candidates(source)
    second = detect_patch_version_candidates(source)

    assert first == second


def test_none_top_level_rejected():
    with pytest.raises(TypeError):
        detect_patch_version_candidates(None)


def test_string_top_level_rejected():
    with pytest.raises(TypeError):
        detect_patch_version_candidates("invalid")


def test_none_item_rejected():
    with pytest.raises(ValueError, match="index 0"):
        detect_patch_version_candidates([None])


def test_unsupported_item_rejected():
    with pytest.raises(TypeError):
        detect_patch_version_candidates([123])


def test_missing_field_rejected():
    with pytest.raises(ValueError):
        detect_patch_version_candidates(
            [
                {
                    "vulnerability_id": "CVE-1",
                    "package_name": "pkg",
                }
            ]
        )


def test_unknown_field_rejected():
    with pytest.raises(TypeError):
        detect_patch_version_candidates(
            [
                {
                    **item(
                        "CVE-1",
                        "pkg",
                        "1.0.0",
                        ["1.0.1"],
                    ),
                    "unexpected": "value",
                }
            ]
        )


def test_fixed_versions_string_rejected():
    with pytest.raises(TypeError):
        detect_patch_version_candidates(
            [
                item(
                    "CVE-1",
                    "pkg",
                    "1.0.0",
                    "1.0.1",
                )
            ]
        )


def test_invalid_version_rejected():
    with pytest.raises(ValueError):
        detect_patch_version_candidates(
            [
                item(
                    "CVE-1",
                    "pkg",
                    "invalid",
                    ["1.0.1"],
                )
            ]
        )


def test_invalid_fixed_version_rejected():
    with pytest.raises(ValueError):
        detect_patch_version_candidates(
            [
                item(
                    "CVE-1",
                    "pkg",
                    "1.0.0",
                    ["invalid"],
                )
            ]
        )


def test_empty_vulnerability_id_rejected():
    with pytest.raises(ValueError):
        detect_patch_version_candidates(
            [
                item(
                    "",
                    "pkg",
                    "1.0.0",
                    ["1.0.1"],
                )
            ]
        )


def test_empty_package_name_rejected():
    with pytest.raises(ValueError):
        detect_patch_version_candidates(
            [
                item(
                    "CVE-1",
                    "",
                    "1.0.0",
                    ["1.0.1"],
                )
            ]
        )


def test_empty_current_version_rejected():
    with pytest.raises(ValueError):
        detect_patch_version_candidates(
            [
                item(
                    "CVE-1",
                    "pkg",
                    "",
                    ["1.0.1"],
                )
            ]
        )


def test_empty_fixed_version_rejected():
    with pytest.raises(ValueError):
        detect_patch_version_candidates(
            [
                item(
                    "CVE-1",
                    "pkg",
                    "1.0.0",
                    [""],
                )
            ]
        )


def test_default_source():
    result = detect_patch_version_candidates(
        [
            {
                "vulnerability_id": "CVE-1",
                "package_name": "pkg",
                "current_version": "1.0.0",
                "fixed_versions": ["1.0.1"],
            }
        ]
    )

    assert result.candidates[0].source == "UNKNOWN"


def test_public_alias():
    source = [
        item(
            "CVE-ALIAS",
            "pkg",
            "1.0.0",
            ["1.0.1"],
        )
    ]

    assert (
        patch_version_candidate_detection(source)
        == detect_patch_version_candidates(source)
    )


def test_result_types():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.0.0",
                ["1.0.1"],
            )
        ]
    )

    assert isinstance(
        result,
        PatchVersionCandidateDetectionResult,
    )

    assert isinstance(
        result.candidates[0],
        PatchVersionCandidate,
    )


def test_zero_major_version():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "0.5.1",
                ["0.5.2"],
            )
        ]
    )

    assert result.total == 1


def test_large_patch_distance():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.2.1",
                ["1.2.100"],
            )
        ]
    )

    assert result.total == 1
    assert result.candidates[0].patch_distance == 99


def test_original_index_recorded():
    result = detect_patch_version_candidates(
        [
            item(
                "CVE-NO-CANDIDATE",
                "a",
                "1.0.0",
                ["1.1.0"],
            ),
            item(
                "CVE-CANDIDATE",
                "b",
                "2.0.0",
                ["2.0.1"],
            ),
        ]
    )

    assert result.candidates[0].original_index == 1
