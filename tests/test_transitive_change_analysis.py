from sentinelshield.transitive_change_analysis import (
    TransitiveChangeAnalysisInput,
    TransitiveDependencyChange,
    analyze_transitive_changes,
    transitive_change_analysis,
)


def test_added_transitive_dependency():
    result = analyze_transitive_changes(
        TransitiveChangeAnalysisInput(
            before={
                "root": {
                    "version": "1.0",
                    "direct": True,
                },
            },
            after={
                "root": {
                    "version": "1.0",
                    "direct": True,
                },
                "child": {
                    "version": "2.0",
                    "parents": ["root"],
                    "direct": False,
                },
            },
        )
    )

    assert len(result.added) == 1
    assert result.added[0].package == "child"
    assert result.added[0].before_version is None
    assert result.added[0].after_version == "2.0"


def test_removed_transitive_dependency():
    result = analyze_transitive_changes(
        TransitiveChangeAnalysisInput(
            before={
                "child": {
                    "version": "1.0",
                    "parents": ["root"],
                    "direct": False,
                },
            },
            after={},
        )
    )

    assert len(result.removed) == 1
    assert result.removed[0].package == "child"
    assert result.removed[0].before_version == "1.0"
    assert result.removed[0].after_version is None


def test_updated_transitive_dependency_version():
    result = analyze_transitive_changes(
        TransitiveChangeAnalysisInput(
            before={
                "child": {
                    "version": "1.0",
                    "parents": ["root"],
                    "direct": False,
                },
            },
            after={
                "child": {
                    "version": "2.0",
                    "parents": ["root"],
                    "direct": False,
                },
            },
        )
    )

    assert len(result.updated) == 1
    assert result.updated[0].package == "child"
    assert result.updated[0].before_version == "1.0"
    assert result.updated[0].after_version == "2.0"


def test_updated_when_parent_dependency_changes():
    result = analyze_transitive_changes(
        TransitiveChangeAnalysisInput(
            before={
                "child": {
                    "version": "1.0",
                    "parents": ["root-a"],
                    "direct": False,
                },
            },
            after={
                "child": {
                    "version": "1.0",
                    "parents": ["root-b"],
                    "direct": False,
                },
            },
        )
    )

    assert len(result.updated) == 1
    assert result.updated[0].package == "child"
    assert result.updated[0].before_parents == ("root-a",)
    assert result.updated[0].after_parents == ("root-b",)


def test_unchanged_transitive_dependency():
    result = analyze_transitive_changes(
        TransitiveChangeAnalysisInput(
            before={
                "child": {
                    "version": "1.0",
                    "parents": ["root"],
                    "direct": False,
                },
            },
            after={
                "child": {
                    "version": "1.0",
                    "parents": ["root"],
                    "direct": False,
                },
            },
        )
    )

    assert len(result.unchanged) == 1
    assert result.unchanged[0].package == "child"


def test_direct_dependency_is_not_analyzed():
    result = analyze_transitive_changes(
        TransitiveChangeAnalysisInput(
            before={
                "direct": {
                    "version": "1.0",
                    "direct": True,
                },
            },
            after={
                "direct": {
                    "version": "2.0",
                    "direct": True,
                },
            },
        )
    )

    assert result.changes == ()


def test_duplicate_parents_are_normalized():
    result = analyze_transitive_changes(
        TransitiveChangeAnalysisInput(
            before={
                "child": {
                    "version": "1.0",
                    "parents": ["root", "root"],
                    "direct": False,
                },
            },
            after={
                "child": {
                    "version": "1.0",
                    "parents": ["root"],
                    "direct": False,
                },
            },
        )
    )

    assert result.unchanged[0].before_parents == ("root",)
    assert result.unchanged[0].after_parents == ("root",)


def test_invalid_input_type():
    try:
        analyze_transitive_changes(None)
    except TypeError as exc:
        assert str(exc) == (
            "INPUT_MUST_BE_TRANSITIVE_CHANGE_ANALYSIS_INPUT"
        )
    else:
        raise AssertionError("TypeError was not raised")


def test_invalid_tree_type():
    request = TransitiveChangeAnalysisInput(
        before=[],
        after={},
    )

    try:
        analyze_transitive_changes(request)
    except TypeError as exc:
        assert str(exc) == "BEFORE_MUST_BE_MAPPING"
    else:
        raise AssertionError("TypeError was not raised")


def test_missing_version_is_rejected():
    request = TransitiveChangeAnalysisInput(
        before={
            "child": {
                "parents": ["root"],
                "direct": False,
            },
        },
        after={},
    )

    try:
        analyze_transitive_changes(request)
    except ValueError as exc:
        assert str(exc) == "BEFORE_PACKAGE_VERSION_REQUIRED"
    else:
        raise AssertionError("ValueError was not raised")


def test_invalid_direct_flag_is_rejected():
    request = TransitiveChangeAnalysisInput(
        before={
            "child": {
                "version": "1.0",
                "direct": "false",
            },
        },
        after={},
    )

    try:
        analyze_transitive_changes(request)
    except TypeError as exc:
        assert str(exc) == "BEFORE_PACKAGE_DIRECT_MUST_BE_BOOL"
    else:
        raise AssertionError("TypeError was not raised")


def test_public_alias_matches_primary_function():
    request = TransitiveChangeAnalysisInput(
        before={
            "child": {
                "version": "1.0",
                "parents": ["root"],
                "direct": False,
            },
        },
        after={
            "child": {
                "version": "2.0",
                "parents": ["root"],
                "direct": False,
            },
        },
    )

    assert transitive_change_analysis(request) == (
        analyze_transitive_changes(request)
    )
