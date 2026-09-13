import sys
from pathlib import Path
import pytest

sys.path.insert(0, "src")

from sentinelshield.test_result_aggregation import (
    TestResultAggregationInput,
    TestResultAggregationResult,
    aggregate_test_results,
    test_result_aggregation,
)

def test_all_pass():
    r = aggregate_test_results(
        TestResultAggregationInput({"unit": "PASS", "integration": "PASS"})
    )
    assert (r.total, r.passed, r.failed) == (2, 2, 0)
    assert r.status == "PASS"

def test_failed():
    r = aggregate_test_results(
        TestResultAggregationInput({"unit": "PASS", "lint": "FAIL"})
    )
    assert r.failed == 1
    assert r.status == "FAIL"

def test_timeout():
    r = aggregate_test_results(
        TestResultAggregationInput({"build": "TIMEOUT"})
    )
    assert r.timed_out == 1
    assert r.status == "FAIL"

def test_error():
    r = aggregate_test_results(
        TestResultAggregationInput({"security": "ERROR"})
    )
    assert r.errors == 1
    assert r.status == "FAIL"

def test_mixed_counts():
    r = aggregate_test_results(
        TestResultAggregationInput(
            {"a": "PASS", "b": "FAIL", "c": "TIMEOUT", "d": "ERROR"}
        )
    )
    assert (r.total, r.passed, r.failed, r.timed_out, r.errors) == (4, 1, 1, 1, 1)

def test_empty_fails():
    r = aggregate_test_results(TestResultAggregationInput({}))
    assert r.total == 0
    assert r.status == "FAIL"

def test_invalid_input():
    with pytest.raises(TypeError):
        aggregate_test_results(None)

def test_invalid_mapping():
    with pytest.raises(TypeError):
        aggregate_test_results(TestResultAggregationInput(None))

def test_invalid_name():
    with pytest.raises(TypeError):
        aggregate_test_results(TestResultAggregationInput({"": "PASS"}))

def test_invalid_status():
    with pytest.raises(ValueError):
        aggregate_test_results(TestResultAggregationInput({"unit": "UNKNOWN"}))

def test_wrapper():
    r = test_result_aggregation(TestResultAggregationInput({"unit": "PASS"}))
    assert isinstance(r, TestResultAggregationResult)
    assert r.status == "PASS"
