from dataclasses import dataclass
from typing import Mapping

__test__ = False

_VALID = {"PASS", "FAIL", "TIMEOUT", "ERROR"}

@dataclass(frozen=True)
class SecurityAcceptanceGateInput:
    vulnerability_status: str
    supply_chain_status: str
    package_integrity_status: str
    package_source_status: str
    lockfile_integrity_status: str
    sbom_status: str
    fixed_vulnerabilities: int = 0
    remaining_vulnerabilities: int = 0
    new_vulnerabilities: int = 0

@dataclass(frozen=True)
class SecurityAcceptanceGateResult:
    accepted: bool
    status: str
    reasons: tuple[str, ...]
    blocking_checks: tuple[str, ...]
    fixed_vulnerabilities: int
    remaining_vulnerabilities: int
    new_vulnerabilities: int

def _status(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name}_MUST_BE_STRING")
    value = value.strip().upper()
    if value not in _VALID:
        raise ValueError(f"{name}_INVALID_STATUS")
    return value

def _count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name}_MUST_BE_NONNEGATIVE_INT")
    if value < 0:
        raise ValueError(f"{name}_MUST_BE_NONNEGATIVE_INT")
    return value

def evaluate_security_acceptance(
    request: SecurityAcceptanceGateInput,
) -> SecurityAcceptanceGateResult:
    if not isinstance(request, SecurityAcceptanceGateInput):
        raise TypeError("INPUT_MUST_BE_SECURITY_ACCEPTANCE_GATE_INPUT")

    fields = {
        "VULNERABILITY_STATUS": request.vulnerability_status,
        "SUPPLY_CHAIN_STATUS": request.supply_chain_status,
        "PACKAGE_INTEGRITY_STATUS": request.package_integrity_status,
        "PACKAGE_SOURCE_STATUS": request.package_source_status,
        "LOCKFILE_INTEGRITY_STATUS": request.lockfile_integrity_status,
        "SBOM_STATUS": request.sbom_status,
    }
    statuses = {k: _status(v, k) for k, v in fields.items()}

    fixed = _count(request.fixed_vulnerabilities, "FIXED_VULNERABILITIES")
    remaining = _count(request.remaining_vulnerabilities, "REMAINING_VULNERABILITIES")
    new = _count(request.new_vulnerabilities, "NEW_VULNERABILITIES")

    blocking = []
    reasons = []

    for name, status in statuses.items():
        if status != "PASS":
            blocking.append(name)
            reasons.append(f"{name}_{status}")

    if remaining:
        blocking.append("REMAINING_VULNERABILITIES")
        reasons.append("REMAINING_VULNERABILITIES_PRESENT")

    if new:
        blocking.append("NEW_VULNERABILITIES")
        reasons.append("NEW_VULNERABILITIES_PRESENT")

    accepted = not blocking
    if accepted:
        status = "PASS"
        reasons = ("SECURITY_ACCEPTANCE_PASSED",)
    else:
        status = "FAIL"

    return SecurityAcceptanceGateResult(
        accepted=accepted,
        status=status,
        reasons=tuple(reasons),
        blocking_checks=tuple(blocking),
        fixed_vulnerabilities=fixed,
        remaining_vulnerabilities=remaining,
        new_vulnerabilities=new,
    )

def security_acceptance_gate(request):
    return evaluate_security_acceptance(request)

security_acceptance_gate.__test__ = False
