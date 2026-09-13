from sentinelshield.source_code_impact_analysis import (
    SourceCodeImpactAnalysisInput,
    SourceCodeImpact,
    analyze_source_code_impact,
    source_code_impact_analysis,
)


def test_changed_file_with_explicit_package_is_affected():
    result = analyze_source_code_impact(
        SourceCodeImpactAnalysisInput(
            changed_files={
                "src/app.py": {
                    "changed": True,
                    "affected_packages": ["requests"],
                    "affected_modules": ["app"],
                }
            },
            dependency_changes={
                "requests": {
                    "before_version": "2.31",
                    "after_version": "2.32",
                }
            },
        )
    )

    assert len(result.affected) == 1
    assert result.affected[0].path == "src/app.py"
    assert result.affected[0].affected_packages == ("requests",)
    assert result.affected[0].affected_modules == ("app",)
    assert result.affected[0].impact_type == "affected"


def test_dependency_name_can_be_matched_to_file_path():
    result = analyze_source_code_impact(
        SourceCodeImpactAnalysisInput(
            changed_files={
                "src/requests/client.py": {
                    "changed": True,
                }
            },
            dependency_changes={
                "requests": {
                    "before_version": "2.31",
                    "after_version": "2.32",
                }
            },
        )
    )

    assert result.affected[0].affected_packages == ("requests",)
    assert result.affected[0].impact_type == "affected"


def test_changed_file_without_match_is_changed():
    result = analyze_source_code_impact(
        SourceCodeImpactAnalysisInput(
            changed_files={
                "src/unrelated.py": {
                    "changed": True,
                }
            },
            dependency_changes={
                "requests": {
                    "before_version": "2.31",
                    "after_version": "2.32",
                }
            },
        )
    )

    assert len(result.impacts) == 1
    assert result.impacts[0].impact_type == "changed"
    assert result.impacts[0].affected_packages == ()


def test_unchanged_file_is_unaffected():
    result = analyze_source_code_impact(
        SourceCodeImpactAnalysisInput(
            changed_files={
                "src/app.py": {
                    "changed": False,
                }
            },
            dependency_changes={},
        )
    )

    assert len(result.unaffected) == 1
    assert result.unaffected[0].impact_type == "unchanged"


def test_duplicate_packages_and_modules_are_normalized():
    result = analyze_source_code_impact(
        SourceCodeImpactAnalysisInput(
            changed_files={
                "src/app.py": {
                    "changed": True,
                    "affected_packages": [
                        "requests",
                        "requests",
                    ],
                    "affected_modules": [
                        "app",
                        "app",
                    ],
                }
            },
            dependency_changes={},
        )
    )

    impact = result.affected[0]

    assert impact.affected_packages == ("requests",)
    assert impact.affected_modules == ("app",)


def test_none_package_and_module_lists_are_empty():
    result = analyze_source_code_impact(
        SourceCodeImpactAnalysisInput(
            changed_files={
                "src/app.py": {
                    "changed": True,
                    "affected_packages": None,
                    "affected_modules": None,
                }
            },
            dependency_changes={},
        )
    )

    impact = result.affected[0]

    assert impact.affected_packages == ()
    assert impact.affected_modules == ()


def test_direct_dependency_change_does_not_implicitly_mark_file():
    result = analyze_source_code_impact(
        SourceCodeImpactAnalysisInput(
            changed_files={
                "src/application.py": {
                    "changed": True,
                }
            },
            dependency_changes={
                "requests": {
                    "before_version": "2.31",
                    "after_version": "2.32",
                }
            },
        )
    )

    assert result.affected[0].impact_type == "changed"


def test_invalid_input_type():
    try:
        analyze_source_code_impact(None)
    except TypeError as exc:
        assert str(exc) == (
            "INPUT_MUST_BE_SOURCE_CODE_IMPACT_ANALYSIS_INPUT"
        )
    else:
        raise AssertionError("TypeError was not raised")


def test_invalid_changed_files_type():
    request = SourceCodeImpactAnalysisInput(
        changed_files=[],
        dependency_changes={},
    )

    try:
        analyze_source_code_impact(request)
    except TypeError as exc:
        assert str(exc) == "CHANGED_FILES_MUST_BE_MAPPING"
    else:
        raise AssertionError("TypeError was not raised")


def test_invalid_dependency_changes_type():
    request = SourceCodeImpactAnalysisInput(
        changed_files={},
        dependency_changes=[],
    )

    try:
        analyze_source_code_impact(request)
    except TypeError as exc:
        assert str(exc) == "DEPENDENCY_CHANGES_MUST_BE_MAPPING"
    else:
        raise AssertionError("TypeError was not raised")


def test_empty_path_is_rejected():
    request = SourceCodeImpactAnalysisInput(
        changed_files={
            "   ": {
                "changed": True,
            }
        },
        dependency_changes={},
    )

    try:
        analyze_source_code_impact(request)
    except ValueError as exc:
        assert str(exc) == (
            "CHANGED_FILE_PATH_MUST_NOT_BE_EMPTY"
        )
    else:
        raise AssertionError("ValueError was not raised")


def test_empty_dependency_name_is_rejected():
    request = SourceCodeImpactAnalysisInput(
        changed_files={},
        dependency_changes={
            "   ": {
                "before_version": "1.0",
                "after_version": "2.0",
            }
        },
    )

    try:
        analyze_source_code_impact(request)
    except ValueError as exc:
        assert str(exc) == (
            "DEPENDENCY_NAME_MUST_NOT_BE_EMPTY"
        )
    else:
        raise AssertionError("ValueError was not raised")


def test_public_alias_matches_primary_function():
    request = SourceCodeImpactAnalysisInput(
        changed_files={
            "src/app.py": {
                "changed": True,
                "affected_packages": ["requests"],
            }
        },
        dependency_changes={},
    )

    assert source_code_impact_analysis(request) == (
        analyze_source_code_impact(request)
    )
