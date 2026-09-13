import pytest

from sentinelshield.dependency_count_comparison import (
    DependencyCountComparisonInput,
    compare_dependency_counts,
)


def test_unchanged_count():
    result = compare_dependency_counts(
        DependencyCountComparisonInput(
            before_count=10,
            after_count=10,
        )
    )

    assert result.status == "UNCHANGED"
    assert result.difference == 0
    assert result.unchanged is True
    assert result.has_change is False


def test_increased_count():
    result = compare_dependency_counts(
        DependencyCountComparisonInput(
            before_count=10,
            after_count=13,
        )
    )

    assert result.status == "INCREASED"
    assert result.difference == 3
    assert result.increased is True


def test_decreased_count():
    result = compare_dependency_counts(
        DependencyCountComparisonInput(
            before_count=13,
            after_count=10,
        )
    )

    assert result.status == "DECREASED"
    assert result.difference == -3
    assert result.decreased is True


def test_zero_counts():
    result = compare_dependency_counts(
        DependencyCountComparisonInput(
            before_count=0,
            after_count=0,
        )
    )

    assert result.status == "UNCHANGED"


def test_before_count_cannot_be_negative():
    with pytest.raises(
        ValueError,
        match="BEFORE_COUNT_MUST_BE_NON_NEGATIVE",
    ):
        compare_dependency_counts(
            DependencyCountComparisonInput(
                before_count=-1,
                after_count=0,
            )
        )


def test_after_count_cannot_be_negative():
    with pytest.raises(
        ValueError,
        match="AFTER_COUNT_MUST_BE_NON_NEGATIVE",
    ):
        compare_dependency_counts(
            DependencyCountComparisonInput(
                before_count=0,
                after_count=-1,
            )
        )


def test_boolean_before_count_is_rejected():
    with pytest.raises(
        TypeError,
        match="BEFORE_COUNT_MUST_BE_INTEGER",
    ):
        compare_dependency_counts(
            DependencyCountComparisonInput(
                before_count=True,
                after_count=1,
            )
        )


def test_boolean_after_count_is_rejected():
    with pytest.raises(
        TypeError,
        match="AFTER_COUNT_MUST_BE_INTEGER",
    ):
        compare_dependency_counts(
            DependencyCountComparisonInput(
                before_count=1,
                after_count=False,
            )
        )


def test_non_integer_before_count_is_rejected():
    with pytest.raises(
        TypeError,
        match="BEFORE_COUNT_MUST_BE_INTEGER",
    ):
        compare_dependency_counts(
            DependencyCountComparisonInput(
                before_count="10",
                after_count=10,
            )
        )


def test_invalid_input_type_is_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_DEPENDENCY_COUNT_COMPARISON_INPUT",
    ):
        compare_dependency_counts(None)
