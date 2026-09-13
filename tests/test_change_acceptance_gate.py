import pytest

from sentinelshield.change_acceptance_gate import (
    ChangeAcceptanceGateInput,
    evaluate_change_acceptance,
)


def test_all_checks_pass():
    r = evaluate_change_acceptance(
        ChangeAcceptanceGateInput("PASS", "PASS", "PASS")
    )
    assert r.accepted is True
    assert r.status == "ACCEPT"
    assert r.reasons == ()


def test_diff_failure_rejects():
    r = evaluate_change_acceptance(
        ChangeAcceptanceGateInput("FAIL", "PASS", "PASS")
    )
    assert r.status == "REJECT"
    assert "DIFF_NOT_ACCEPTED" in r.reasons


def test_risk_failure_rejects():
    r = evaluate_change_acceptance(
        ChangeAcceptanceGateInput("PASS", "FAIL", "PASS")
    )
    assert r.accepted is False
    assert "RISK_NOT_ACCEPTED" in r.reasons


def test_validation_failure_rejects():
    r = evaluate_change_acceptance(
        ChangeAcceptanceGateInput("PASS", "PASS", "FAIL")
    )
    assert r.accepted is False
    assert "VALIDATION_NOT_ACCEPTED" in r.reasons


def test_multiple_failures_are_reported():
    r = evaluate_change_acceptance(
        ChangeAcceptanceGateInput("FAIL", "FAIL", "FAIL")
    )
    assert len(r.reasons) == 3


def test_risk_other_than_fail_is_not_rejected():
    r = evaluate_change_acceptance(
        ChangeAcceptanceGateInput("PASS", "INCREASED", "PASS")
    )
    assert r.accepted is True


def test_input_type_rejected():
    with pytest.raises(TypeError):
        evaluate_change_acceptance(None)


def test_diff_type_rejected():
    with pytest.raises(TypeError):
        evaluate_change_acceptance(
            ChangeAcceptanceGateInput(1, "PASS", "PASS")
        )


def test_empty_status_rejected():
    with pytest.raises(ValueError):
        evaluate_change_acceptance(
            ChangeAcceptanceGateInput("", "PASS", "PASS")
        )


def test_result_is_deterministic():
    request = ChangeAcceptanceGateInput("FAIL", "FAIL", "FAIL")
    assert evaluate_change_acceptance(request) == evaluate_change_acceptance(request)
