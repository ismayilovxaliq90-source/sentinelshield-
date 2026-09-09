import pytest

from sentinelshield.fixed_version_candidate_discovery import (
    FixedVersionCandidate,
    FixedVersionCandidateDiscoveryResult,
    FixedVersionDiscoveryInput,
    discover_fixed_version_candidates,
    fixed_version_candidate_discovery,
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
    result = discover_fixed_version_candidates([])

    assert result.candidates == ()
    assert result.total == 0
    assert result.vulnerabilities_processed == 0


def test_discovers_fixed_version():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "requests",
                "2.31.0",
                ["2.32.0"],
            )
        ]
    )

    assert result.total == 1

    candidate = result.candidates[0]

    assert candidate.vulnerability_id == "CVE-1"
    assert candidate.package_name == "requests"
    assert candidate.current_version == "2.31.0"
    assert candidate.fixed_version == "2.32.0"
    assert candidate.source == "OSV"
    assert candidate.is_upgrade is True


def test_older_fixed_version_is_not_candidate():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "2.5.0",
                ["2.4.0"],
            )
        ]
    )

    assert result.total == 0


def test_equal_current_version_is_not_candidate():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "2.5.0",
                ["2.5.0"],
            )
        ]
    )

    assert result.total == 0


def test_multiple_fixed_versions_are_discovered():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.0.0",
                ["1.1.0", "1.2.0", "2.0.0"],
            )
        ]
    )

    assert [x.fixed_version for x in result.candidates] == [
        "1.1.0",
        "1.2.0",
        "2.0.0",
    ]


def test_duplicate_fixed_versions_are_removed():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.0.0",
                ["1.1.0", "1.1.0", "1.2.0"],
            )
        ]
    )

    assert [x.fixed_version for x in result.candidates] == [
        "1.1.0",
        "1.2.0",
    ]


def test_multiple_vulnerabilities():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg-a",
                "1.0.0",
                ["1.1.0"],
            ),
            item(
                "CVE-2",
                "pkg-b",
                "3.0.0",
                ["3.1.0", "4.0.0"],
            ),
        ]
    )

    assert result.total == 3
    assert result.vulnerabilities_processed == 2


def test_input_order_is_preserved():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-A",
                "a",
                "1.0.0",
                ["1.1.0"],
            ),
            item(
                "CVE-B",
                "b",
                "1.0.0",
                ["1.1.0"],
            ),
        ]
    )

    assert [x.vulnerability_id for x in result.candidates] == [
        "CVE-A",
        "CVE-B",
    ]


def test_version_order_is_deterministic():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.0.0",
                ["2.0.0", "1.2.0", "1.10.0"],
            )
        ]
    )

    assert [x.fixed_version for x in result.candidates] == [
        "1.2.0",
        "1.10.0",
        "2.0.0",
    ]


def test_dataclass_input():
    data = FixedVersionDiscoveryInput(
        vulnerability_id="CVE-DATA",
        package_name="urllib3",
        current_version="1.26.0",
        fixed_versions=("1.26.18",),
        source="OSV",
    )

    result = discover_fixed_version_candidates([data])

    assert result.total == 1
    assert result.candidates[0].fixed_version == "1.26.18"


def test_mapping_input():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-MAP",
                "flask",
                "2.0.0",
                ["2.3.0"],
            )
        ]
    )

    assert result.total == 1


def test_input_is_not_mutated():
    source = [
        item(
            "CVE-1",
            "pkg",
            "1.0.0",
            ["1.1.0", "1.2.0"],
        )
    ]

    original = [dict(x) for x in source]
    original[0]["fixed_versions"] = list(
        original[0]["fixed_versions"]
    )

    discover_fixed_version_candidates(source)

    assert source[0]["vulnerability_id"] == original[0]["vulnerability_id"]
    assert source[0]["package_name"] == original[0]["package_name"]
    assert source[0]["current_version"] == original[0]["current_version"]
    assert source[0]["fixed_versions"] == original[0]["fixed_versions"]


def test_deterministic_result():
    source = [
        item(
            "CVE-1",
            "pkg",
            "1.0.0",
            ["1.2.0", "1.1.0"],
        )
    ]

    first = discover_fixed_version_candidates(source)
    second = discover_fixed_version_candidates(source)

    assert first == second


def test_none_top_level_rejected():
    with pytest.raises(TypeError):
        discover_fixed_version_candidates(None)


def test_string_top_level_rejected():
    with pytest.raises(TypeError):
        discover_fixed_version_candidates("invalid")


def test_none_item_rejected():
    with pytest.raises(ValueError, match="index 0"):
        discover_fixed_version_candidates([None])


def test_unsupported_item_rejected():
    with pytest.raises(TypeError):
        discover_fixed_version_candidates([123])


def test_missing_required_field_rejected():
    with pytest.raises(ValueError):
        discover_fixed_version_candidates(
            [
                {
                    "vulnerability_id": "CVE-1",
                    "package_name": "pkg",
                }
            ]
        )


def test_unknown_field_rejected():
    with pytest.raises(TypeError):
        discover_fixed_version_candidates(
            [
                {
                    **item(
                        "CVE-1",
                        "pkg",
                        "1.0.0",
                        ["1.1.0"],
                    ),
                    "unexpected": "value",
                }
            ]
        )


def test_fixed_versions_string_rejected():
    with pytest.raises(TypeError):
        discover_fixed_version_candidates(
            [
                item(
                    "CVE-1",
                    "pkg",
                    "1.0.0",
                    "1.1.0",
                )
            ]
        )


def test_empty_vulnerability_id_rejected():
    with pytest.raises(ValueError):
        discover_fixed_version_candidates(
            [
                item(
                    "",
                    "pkg",
                    "1.0.0",
                    ["1.1.0"],
                )
            ]
        )


def test_empty_package_name_rejected():
    with pytest.raises(ValueError):
        discover_fixed_version_candidates(
            [
                item(
                    "CVE-1",
                    "",
                    "1.0.0",
                    ["1.1.0"],
                )
            ]
        )


def test_empty_current_version_rejected():
    with pytest.raises(ValueError):
        discover_fixed_version_candidates(
            [
                item(
                    "CVE-1",
                    "pkg",
                    "",
                    ["1.1.0"],
                )
            ]
        )


def test_empty_fixed_version_rejected():
    with pytest.raises(ValueError):
        discover_fixed_version_candidates(
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
    result = discover_fixed_version_candidates(
        [
            {
                "vulnerability_id": "CVE-1",
                "package_name": "pkg",
                "current_version": "1.0.0",
                "fixed_versions": ["1.1.0"],
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
            ["1.1.0"],
        )
    ]

    assert (
        fixed_version_candidate_discovery(source)
        == discover_fixed_version_candidates(source)
    )


def test_result_types():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.0.0",
                ["1.1.0"],
            )
        ]
    )

    assert isinstance(
        result,
        FixedVersionCandidateDiscoveryResult,
    )
    assert isinstance(
        result.candidates[0],
        FixedVersionCandidate,
    )


def test_major_upgrade_is_discovered():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-1",
                "pkg",
                "1.9.9",
                ["2.0.0"],
            )
        ]
    )

    assert result.total == 1
    assert result.candidates[0].fixed_version == "2.0.0"


def test_candidate_records_original_index():
    result = discover_fixed_version_candidates(
        [
            item(
                "CVE-FIRST",
                "a",
                "1.0.0",
                ["1.1.0"],
            ),
            item(
                "CVE-SECOND",
                "b",
                "1.0.0",
                ["1.1.0"],
            ),
        ]
    )

    assert result.candidates[0].original_index == 0
    assert result.candidates[1].original_index == 1
