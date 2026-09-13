import pytest

from sentinelshield.import_compatibility_analysis import (
    ImportCompatibility,
    ImportCompatibilityAnalysisInput,
    analyze_import_compatibility,
    import_compatibility_analysis,
)


def test_no_dependency_change_is_compatible():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "requests.api": {"package": "requests"},
        },
        dependency_changes={},
    )

    result = analyze_import_compatibility(request)

    assert result.results == (
        ImportCompatibility(
            module="requests.api",
            package="requests",
            compatible=True,
            reason="NO_DEPENDENCY_CHANGE",
        ),
    )


def test_removed_module_is_incompatible():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "old_api": {"package": "demo"},
        },
        dependency_changes={
            "demo": {
                "removed_modules": ("old_api",),
            },
        },
    )

    result = analyze_import_compatibility(request)

    assert result.incompatible[0].module == "old_api"
    assert result.incompatible[0].compatible is False
    assert result.incompatible[0].reason == "IMPORTED_MODULE_REMOVED"


def test_incompatible_module_is_incompatible():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "demo.api": {"package": "demo"},
        },
        dependency_changes={
            "demo": {
                "incompatible_modules": ("demo.api",),
            },
        },
    )

    result = analyze_import_compatibility(request)

    assert result.incompatible[0].reason == (
        "IMPORTED_MODULE_INCOMPATIBLE"
    )


def test_unaffected_module_remains_compatible():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "demo.api": {"package": "demo"},
        },
        dependency_changes={
            "demo": {
                "removed_modules": ("demo.old",),
                "incompatible_modules": ("demo.other",),
            },
        },
    )

    result = analyze_import_compatibility(request)

    assert result.compatible[0].reason == (
        "IMPORT_REMAINS_COMPATIBLE"
    )


def test_compatible_and_incompatible_are_partitioned():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "demo.api": {"package": "demo"},
            "demo.old": {"package": "demo"},
        },
        dependency_changes={
            "demo": {
                "removed_modules": ("demo.old",),
            },
        },
    )

    result = analyze_import_compatibility(request)

    assert len(result.compatible) == 1
    assert len(result.incompatible) == 1


def test_string_module_change_is_supported():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "demo.api": {"package": "demo"},
        },
        dependency_changes={
            "demo": {
                "removed_modules": "demo.api",
            },
        },
    )

    result = analyze_import_compatibility(request)

    assert result.incompatible[0].module == "demo.api"


def test_results_are_sorted_by_module():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "z.module": {"package": "z"},
            "a.module": {"package": "a"},
        },
        dependency_changes={},
    )

    result = analyze_import_compatibility(request)

    assert tuple(item.module for item in result.results) == (
        "a.module",
        "z.module",
    )


def test_invalid_request_type():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_IMPORT_COMPATIBILITY_ANALYSIS_INPUT",
    ):
        analyze_import_compatibility(None)


def test_imports_must_be_mapping():
    request = ImportCompatibilityAnalysisInput(
        imports=[],
        dependency_changes={},
    )

    with pytest.raises(
        TypeError,
        match="IMPORTS_MUST_BE_MAPPING",
    ):
        analyze_import_compatibility(request)


def test_import_module_must_be_string():
    request = ImportCompatibilityAnalysisInput(
        imports={
            1: {"package": "demo"},
        },
        dependency_changes={},
    )

    with pytest.raises(
        TypeError,
        match="IMPORT_MODULE_MUST_BE_STRING",
    ):
        analyze_import_compatibility(request)


def test_import_package_must_be_string():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "demo.api": {"package": 123},
        },
        dependency_changes={},
    )

    with pytest.raises(
        TypeError,
        match="IMPORT_PACKAGE_MUST_BE_STRING",
    ):
        analyze_import_compatibility(request)


def test_dependency_metadata_must_be_mapping():
    request = ImportCompatibilityAnalysisInput(
        imports={},
        dependency_changes={
            "demo": None,
        },
    )

    with pytest.raises(
        TypeError,
        match="DEPENDENCY_METADATA_MUST_BE_MAPPING",
    ):
        analyze_import_compatibility(request)


def test_alias_matches_main_function():
    request = ImportCompatibilityAnalysisInput(
        imports={
            "demo.api": {"package": "demo"},
        },
        dependency_changes={},
    )

    assert import_compatibility_analysis(request) == (
        analyze_import_compatibility(request)
    )
