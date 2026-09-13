import pytest

from sentinelshield.test_impact_analysis import (
    TestImpactAnalysisInput,
    analyze_test_impact,
)


def test_no_changed_files():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=(),
            test_files=("tests/test_api.py",),
            test_dependencies={},
        )
    )

    assert result.affected == ()
    assert result.impacts[0].reason == "NO_CHANGED_FILES"


def test_direct_test_change():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=("tests/test_api.py",),
            test_files=("tests/test_api.py",),
            test_dependencies={},
        )
    )

    assert result.affected[0].impact == "DIRECT"
    assert result.affected[0].reason == "TEST_FILE_CHANGED"


def test_related_source_change():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=("src/api.py",),
            test_files=("tests/test_api.py",),
            test_dependencies={},
        )
    )

    assert result.affected[0].reason == "RELATED_SOURCE_CHANGED"


def test_declared_dependency_change():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=("src/service.py",),
            test_files=("tests/test_api.py",),
            test_dependencies={
                "tests/test_api.py": ("src/service.py",),
            },
        )
    )

    assert result.affected[0].reason == (
        "DECLARED_TEST_DEPENDENCY_CHANGED"
    )


def test_unrelated_source_is_not_affected():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=("src/database.py",),
            test_files=("tests/test_api.py",),
            test_dependencies={},
        )
    )

    assert result.affected == ()
    assert result.unaffected[0].reason == "TEST_UNAFFECTED"


def test_results_are_sorted():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=("src/api.py",),
            test_files=(
                "tests/test_z.py",
                "tests/test_a.py",
            ),
            test_dependencies={},
        )
    )

    assert [item.test for item in result.impacts] == [
        "tests/test_a.py",
        "tests/test_z.py",
    ]


def test_changed_file_normalization():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=("./src/api.py",),
            test_files=("tests/test_api.py",),
            test_dependencies={},
        )
    )

    assert result.affected[0].affected is True


def test_invalid_input_type():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_TEST_IMPACT_ANALYSIS_INPUT",
    ):
        analyze_test_impact(None)


def test_changed_file_must_be_string():
    with pytest.raises(
        TypeError,
        match="CHANGED_FILE_MUST_BE_STRING",
    ):
        analyze_test_impact(
            TestImpactAnalysisInput(
                changed_files=(1,),
                test_files=(),
                test_dependencies={},
            )
        )


def test_test_dependency_mapping_is_used():
    result = analyze_test_impact(
        TestImpactAnalysisInput(
            changed_files=("src/config.py",),
            test_files=(
                "tests/test_runtime.py",
                "tests/test_api.py",
            ),
            test_dependencies={
                "tests/test_runtime.py": ("src/config.py",),
            },
        )
    )

    assert result.affected == (
        result.impacts[1],
    )
    assert result.impacts[1].reason == (
        "DECLARED_TEST_DEPENDENCY_CHANGED"
    )
