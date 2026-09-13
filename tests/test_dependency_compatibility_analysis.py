from sentinelshield.dependency_compatibility_analysis import (
    DependencyCompatibilityAnalysisInput,
    DependencyCompatibilityAnalysisResult,
    analyze_dependency_compatibility,
    dependency_compatibility_analysis,
)


def test_no_dependency_change():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={"requests": {"package": "urllib3"}},
        dependency_changes={},
    )

    result = analyze_dependency_compatibility(request)

    assert result.impacts[0].impact == "NONE"
    assert result.impacts[0].affected is False
    assert result.impacts[0].reason == "NO_DEPENDENCY_CHANGE"


def test_incompatible_dependency_is_breaking():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={"app": {"package": "requests"}},
        dependency_changes={
            "requests": {
                "incompatible_dependencies": ("app",),
            }
        },
    )

    result = analyze_dependency_compatibility(request)

    assert result.impacts[0].impact == "BREAKING"
    assert result.impacts[0].affected is True
    assert result.impacts[0].reason == "DEPENDENCY_INCOMPATIBLE"


def test_changed_dependency_is_changed():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={"app": {"package": "requests"}},
        dependency_changes={
            "requests": {
                "changed_dependencies": ("app",),
            }
        },
    )

    result = analyze_dependency_compatibility(request)

    assert result.impacts[0].impact == "CHANGED"
    assert result.impacts[0].affected is True


def test_unaffected_dependency():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={"app": {"package": "requests"}},
        dependency_changes={
            "requests": {
                "changed_dependencies": ("other",),
            }
        },
    )

    result = analyze_dependency_compatibility(request)

    assert result.impacts[0].impact == "NONE"
    assert result.impacts[0].affected is False


def test_affected_and_unaffected_groups():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={
            "a": {"package": "requests"},
            "b": {"package": "urllib3"},
        },
        dependency_changes={
            "requests": {
                "changed_dependencies": ("a",),
            }
        },
    )

    result = analyze_dependency_compatibility(request)

    assert tuple(item.dependency for item in result.affected) == ("a",)
    assert tuple(item.dependency for item in result.unaffected) == ("b",)


def test_deterministic_order():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={
            "z": {"package": "pkg-z"},
            "a": {"package": "pkg-a"},
            "m": {"package": "pkg-m"},
        },
        dependency_changes={},
    )

    result = analyze_dependency_compatibility(request)

    assert tuple(item.dependency for item in result.impacts) == (
        "a",
        "m",
        "z",
    )


def test_alias_function():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={"app": {"package": "requests"}},
        dependency_changes={},
    )

    result = dependency_compatibility_analysis(request)

    assert isinstance(result, DependencyCompatibilityAnalysisResult)
    assert result.impacts[0].dependency == "app"


def test_invalid_request_type():
    try:
        analyze_dependency_compatibility(None)
    except TypeError as exc:
        assert str(exc) == (
            "INPUT_MUST_BE_DEPENDENCY_COMPATIBILITY_ANALYSIS_INPUT"
        )
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_dependencies_type():
    request = DependencyCompatibilityAnalysisInput(
        dependencies=None,
        dependency_changes={},
    )

    try:
        analyze_dependency_compatibility(request)
    except TypeError as exc:
        assert str(exc) == "DEPENDENCIES_MUST_BE_MAPPING"
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_dependency_changes_type():
    request = DependencyCompatibilityAnalysisInput(
        dependencies={},
        dependency_changes=None,
    )

    try:
        analyze_dependency_compatibility(request)
    except TypeError as exc:
        assert str(exc) == "DEPENDENCY_CHANGES_MUST_BE_MAPPING"
    else:
        raise AssertionError("Expected TypeError")
