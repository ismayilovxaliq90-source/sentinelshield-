from dataclasses import FrozenInstanceError

import pytest

from sentinelshield.fixed_version_extraction import (
    FixedVersion,
    FixedVersionExtractionResult,
    extract_fixed_version,
    extract_fixed_versions,
)


def test_extract_fixed_version_from_fixed_version():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixed_version": "2.32.0",
        }
    )

    assert result.extracted is True
    assert result.status == "FIXED_VERSIONS_EXTRACTED"
    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_extract_fixed_version_from_fixed_version_alias():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixedVersion": "2.32.0",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_extract_fixed_version_from_fixed_alias():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixed": "2.32.0",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_extract_fixed_version_from_patched_version():
    result = extract_fixed_version(
        {
            "package": "requests",
            "patched_version": "2.32.0",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_extract_fixed_version_from_patched_version_alias():
    result = extract_fixed_version(
        {
            "package": "requests",
            "patchedVersion": "2.32.0",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_extract_fixed_version_from_patched_alias():
    result = extract_fixed_version(
        {
            "package": "requests",
            "patched": "2.32.0",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_multiple_fixed_versions():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixed_version": ["2.31.0", "2.32.0"],
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.31.0"),
        FixedVersion("requests", "2.32.0"),
    )


def test_duplicate_fixed_versions_are_removed():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixed_version": [
                "2.32.0",
                "2.32.0",
                " 2.32.0 ",
            ],
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_whitespace_is_normalized():
    result = extract_fixed_version(
        {
            "package": "  requests  ",
            "fixed_version": " 2.32.0 ",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_package_name_alias():
    result = extract_fixed_version(
        {
            "package_name": "requests",
            "fixed_version": "2.32.0",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_name_alias():
    result = extract_fixed_version(
        {
            "name": "requests",
            "fixed_version": "2.32.0",
        }
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_none_input():
    result = extract_fixed_versions(None)

    assert result.extracted is False
    assert result.status == "VULNERABILITIES_IS_NONE"
    assert result.fixed_versions == ()


def test_empty_collection():
    result = extract_fixed_versions([])

    assert result.extracted is False
    assert result.status == "NO_VULNERABILITIES"


def test_unsupported_collection():
    result = extract_fixed_versions(123)

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_bytes_are_rejected_as_collection():
    result = extract_fixed_versions(b"requests")

    assert result.extracted is False
    assert result.status == "UNSUPPORTED_VULNERABILITY_COLLECTION"


def test_string_is_single_vulnerability():
    result = extract_fixed_versions("requests")

    assert result.extracted is False
    assert result.status == "NO_FIXED_VERSIONS"


def test_missing_package_is_ignored():
    result = extract_fixed_version(
        {
            "fixed_version": "2.32.0",
        }
    )

    assert result.extracted is False
    assert result.status == "NO_FIXED_VERSIONS"


def test_missing_fixed_version_is_reported():
    result = extract_fixed_version(
        {
            "package": "requests",
        }
    )

    assert result.extracted is False
    assert result.status == "NO_FIXED_VERSIONS"


def test_empty_fixed_version_is_reported():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixed_version": "   ",
        }
    )

    assert result.extracted is False
    assert result.status == "NO_FIXED_VERSIONS"


def test_multiple_vulnerabilities():
    result = extract_fixed_versions(
        [
            {
                "package": "requests",
                "fixed_version": "2.32.0",
            },
            {
                "package": "urllib3",
                "fixed_version": "2.2.2",
            },
        ]
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
        FixedVersion("urllib3", "2.2.2"),
    )


def test_deterministic_sorting():
    result = extract_fixed_versions(
        [
            {
                "package": "urllib3",
                "fixed_version": "2.2.2",
            },
            {
                "package": "requests",
                "fixed_version": "2.32.0",
            },
        ]
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
        FixedVersion("urllib3", "2.2.2"),
    )


def test_input_is_not_modified():
    vulnerabilities = [
        {
            "package": "requests",
            "fixed_version": ["2.32.0", "2.31.0"],
        }
    ]

    original = repr(vulnerabilities)

    extract_fixed_versions(vulnerabilities)

    assert repr(vulnerabilities) == original


def test_result_is_immutable():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixed_version": "2.32.0",
        }
    )

    with pytest.raises(FrozenInstanceError):
        result.extracted = False


def test_fixed_version_is_immutable():
    value = FixedVersion("requests", "2.32.0")

    with pytest.raises(FrozenInstanceError):
        value.version = "3.0.0"


def test_result_types():
    result = extract_fixed_version(
        {
            "package": "requests",
            "fixed_version": "2.32.0",
        }
    )

    assert isinstance(result, FixedVersionExtractionResult)
    assert isinstance(result.fixed_versions, tuple)
    assert isinstance(result.fixed_versions[0], FixedVersion)


def test_object_input():
    class Vulnerability:
        package = "requests"
        fixed_version = "2.32.0"

    result = extract_fixed_version(Vulnerability())

    assert result.fixed_versions == (
        FixedVersion("requests", "2.32.0"),
    )


def test_only_supported_fields_are_used():
    result = extract_fixed_version(
        {
            "package": "requests",
            "unrelated_version": "2.32.0",
        }
    )

    assert result.status == "NO_FIXED_VERSIONS"


def test_lowercase_package_order():
    result = extract_fixed_versions(
        [
            {
                "package": "Requests",
                "fixed_version": "2.32.0",
            },
            {
                "package": "requests",
                "fixed_version": "2.31.0",
            },
        ]
    )

    assert result.fixed_versions == (
        FixedVersion("requests", "2.31.0"),
        FixedVersion("Requests", "2.32.0"),
    )
