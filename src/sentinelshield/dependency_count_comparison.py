from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


__test__ = False


@dataclass(frozen=True)
class DependencyCountComparisonInput:
    before_count: int
    after_count: int


@dataclass(frozen=True)
class DependencyCountComparisonResult:
    before_count: int
    after_count: int
    difference: int
    status: str

    @property
    def increased(self) -> bool:
        return self.difference > 0

    @property
    def decreased(self) -> bool:
        return self.difference < 0

    @property
    def unchanged(self) -> bool:
        return self.difference == 0

    @property
    def has_change(self) -> bool:
        return self.difference != 0


def _validate_input(
    request: DependencyCountComparisonInput,
) -> DependencyCountComparisonInput:
    if not isinstance(
        request,
        DependencyCountComparisonInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_DEPENDENCY_COUNT_COMPARISON_INPUT"
        )

    if isinstance(request.before_count, bool):
        raise TypeError("BEFORE_COUNT_MUST_BE_INTEGER")

    if not isinstance(request.before_count, int):
        raise TypeError("BEFORE_COUNT_MUST_BE_INTEGER")

    if isinstance(request.after_count, bool):
        raise TypeError("AFTER_COUNT_MUST_BE_INTEGER")

    if not isinstance(request.after_count, int):
        raise TypeError("AFTER_COUNT_MUST_BE_INTEGER")

    if request.before_count < 0:
        raise ValueError("BEFORE_COUNT_MUST_BE_NON_NEGATIVE")

    if request.after_count < 0:
        raise ValueError("AFTER_COUNT_MUST_BE_NON_NEGATIVE")

    return request


def compare_dependency_counts(
    request: DependencyCountComparisonInput,
) -> DependencyCountComparisonResult:
    request = _validate_input(request)

    difference = request.after_count - request.before_count

    if difference > 0:
        status = "INCREASED"
    elif difference < 0:
        status = "DECREASED"
    else:
        status = "UNCHANGED"

    return DependencyCountComparisonResult(
        before_count=request.before_count,
        after_count=request.after_count,
        difference=difference,
        status=status,
    )


def dependency_count_comparison(
    request: DependencyCountComparisonInput,
) -> DependencyCountComparisonResult:
    return compare_dependency_counts(request)
