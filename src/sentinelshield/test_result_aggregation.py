from dataclasses import dataclass
from typing import Mapping

__test__ = False

@dataclass(frozen=True)
class TestResultAggregationInput:
    results: Mapping[str, str]

@dataclass(frozen=True)
class TestResultAggregationResult:
    total: int
    passed: int
    failed: int
    timed_out: int
    errors: int
    status: str

_VALID = frozenset({"PASS", "FAIL", "TIMEOUT", "ERROR"})

def aggregate_test_results(request):
    if not isinstance(request, TestResultAggregationInput):
        raise TypeError("INPUT_MUST_BE_TEST_RESULT_AGGREGATION_INPUT")
    if not isinstance(request.results, Mapping):
        raise TypeError("RESULTS_MUST_BE_MAPPING")
    for name, status in request.results.items():
        if not isinstance(name, str) or not name.strip():
            raise TypeError("RESULT_NAMES_MUST_BE_NON_EMPTY_STRINGS")
        if not isinstance(status, str) or status not in _VALID:
            raise ValueError("INVALID_TEST_RESULT_STATUS")
    total = len(request.results)
    passed = sum(v == "PASS" for v in request.results.values())
    failed = sum(v == "FAIL" for v in request.results.values())
    timed_out = sum(v == "TIMEOUT" for v in request.results.values())
    errors = sum(v == "ERROR" for v in request.results.values())
    status = "PASS" if total and failed == 0 and timed_out == 0 and errors == 0 else "FAIL"
    if total == 0:
        status = "FAIL"
    return TestResultAggregationResult(
        total, passed, failed, timed_out, errors, status
    )

def test_result_aggregation(request):
    return aggregate_test_results(request)

test_result_aggregation.__test__ = False
