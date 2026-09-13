from dataclasses import dataclass

__test__ = False

@dataclass(frozen=True)
class TestAcceptanceGateInput:
    test_status: str
    security_status: str = "PASS"

@dataclass(frozen=True)
class TestAcceptanceGateResult:
    accepted: bool
    test_status: str
    security_status: str
    status: str
    reason: str

_VALID = frozenset({"PASS", "FAIL", "TIMEOUT", "ERROR"})

def validate_test_acceptance_gate(request):
    if not isinstance(request, TestAcceptanceGateInput):
        raise TypeError("INPUT_MUST_BE_TEST_ACCEPTANCE_GATE_INPUT")
    if not isinstance(request.test_status, str) or request.test_status not in _VALID:
        raise ValueError("INVALID_TEST_STATUS")
    if not isinstance(request.security_status, str) or request.security_status not in _VALID:
        raise ValueError("INVALID_SECURITY_STATUS")

    accepted = request.test_status == "PASS" and request.security_status == "PASS"
    reason = "ALL_REQUIRED_VALIDATIONS_PASSED" if accepted else (
        "TEST_VALIDATION_FAILED" if request.test_status != "PASS"
        else "SECURITY_VALIDATION_FAILED"
    )

    return TestAcceptanceGateResult(
        accepted=accepted,
        test_status=request.test_status,
        security_status=request.security_status,
        status="PASS" if accepted else "FAIL",
        reason=reason,
    )

def test_acceptance_gate(request):
    return validate_test_acceptance_gate(request)

test_acceptance_gate.__test__ = False
