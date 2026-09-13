from sentinelshield.security_acceptance_gate import (
    SecurityAcceptanceGateInput,
    SecurityAcceptanceGateResult,
    evaluate_security_acceptance,
    security_acceptance_gate,
)
import pytest

BASE = dict(
    vulnerability_status="PASS",
    supply_chain_status="PASS",
    package_integrity_status="PASS",
    package_source_status="PASS",
    lockfile_integrity_status="PASS",
    sbom_status="PASS",
)

def test_all_pass():
    r = evaluate_security_acceptance(SecurityAcceptanceGateInput(**BASE))
    assert r.accepted and r.status == "PASS"

@pytest.mark.parametrize("field", [
    "vulnerability_status", "supply_chain_status",
    "package_integrity_status", "package_source_status",
    "lockfile_integrity_status", "sbom_status",
])
def test_failed_check_blocks(field):
    x = BASE.copy()
    x[field] = "FAIL"
    r = evaluate_security_acceptance(SecurityAcceptanceGateInput(**x))
    assert not r.accepted and field.upper() in r.blocking_checks

def test_remaining_vulnerabilities_block():
    r = evaluate_security_acceptance(
        SecurityAcceptanceGateInput(**BASE, remaining_vulnerabilities=1)
    )
    assert not r.accepted
    assert "REMAINING_VULNERABILITIES" in r.blocking_checks

def test_new_vulnerabilities_block():
    r = evaluate_security_acceptance(
        SecurityAcceptanceGateInput(**BASE, new_vulnerabilities=1)
    )
    assert not r.accepted

def test_fixed_vulnerabilities_are_allowed():
    r = evaluate_security_acceptance(
        SecurityAcceptanceGateInput(**BASE, fixed_vulnerabilities=3)
    )
    assert r.accepted and r.fixed_vulnerabilities == 3

def test_invalid_input_type():
    with pytest.raises(TypeError):
        evaluate_security_acceptance(None)

def test_invalid_status():
    x = BASE.copy()
    x["sbom_status"] = "BAD"
    with pytest.raises(ValueError):
        evaluate_security_acceptance(SecurityAcceptanceGateInput(**x))

def test_bool_count_rejected():
    with pytest.raises(TypeError):
        evaluate_security_acceptance(
            SecurityAcceptanceGateInput(**BASE, new_vulnerabilities=True)
        )

def test_negative_count_rejected():
    with pytest.raises(ValueError):
        evaluate_security_acceptance(
            SecurityAcceptanceGateInput(**BASE, remaining_vulnerabilities=-1)
        )

def test_result_shape():
    r = evaluate_security_acceptance(SecurityAcceptanceGateInput(**BASE))
    assert isinstance(r, SecurityAcceptanceGateResult)
    assert isinstance(r.reasons, tuple)
    assert isinstance(r.blocking_checks, tuple)

def test_wrapper():
    r = security_acceptance_gate(SecurityAcceptanceGateInput(**BASE))
    assert r.accepted is True
