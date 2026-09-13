import sys
import pytest

sys.path.insert(0, "src")

from sentinelshield.test_acceptance_gate import (
    TestAcceptanceGateInput,
    TestAcceptanceGateResult,
    validate_test_acceptance_gate,
    test_acceptance_gate,
)

def test_all_pass():
    r = validate_test_acceptance_gate(TestAcceptanceGateInput("PASS", "PASS"))
    assert r.accepted is True
    assert r.status == "PASS"
    assert r.reason == "ALL_REQUIRED_VALIDATIONS_PASSED"

def test_test_failure():
    r = validate_test_acceptance_gate(TestAcceptanceGateInput("FAIL", "PASS"))
    assert r.accepted is False
    assert r.status == "FAIL"
    assert r.reason == "TEST_VALIDATION_FAILED"

def test_test_timeout():
    r = validate_test_acceptance_gate(TestAcceptanceGateInput("TIMEOUT", "PASS"))
    assert r.accepted is False
    assert r.status == "FAIL"

def test_test_error():
    r = validate_test_acceptance_gate(TestAcceptanceGateInput("ERROR", "PASS"))
    assert r.accepted is False
    assert r.status == "FAIL"

def test_security_failure():
    r = validate_test_acceptance_gate(TestAcceptanceGateInput("PASS", "FAIL"))
    assert r.accepted is False
    assert r.reason == "SECURITY_VALIDATION_FAILED"

def test_security_timeout():
    r = validate_test_acceptance_gate(TestAcceptanceGateInput("PASS", "TIMEOUT"))
    assert r.accepted is False

def test_wrong_input():
    with pytest.raises(TypeError):
        validate_test_acceptance_gate(None)

def test_invalid_test_status():
    with pytest.raises(ValueError):
        validate_test_acceptance_gate(TestAcceptanceGateInput("UNKNOWN"))

def test_invalid_security_status():
    with pytest.raises(ValueError):
        validate_test_acceptance_gate(TestAcceptanceGateInput("PASS", "UNKNOWN"))

def test_result_shape():
    r = validate_test_acceptance_gate(TestAcceptanceGateInput("PASS", "PASS"))
    assert isinstance(r, TestAcceptanceGateResult)
    assert r.test_status == "PASS"
    assert r.security_status == "PASS"

def test_wrapper():
    r = test_acceptance_gate(TestAcceptanceGateInput("PASS", "PASS"))
    assert r.accepted is True
