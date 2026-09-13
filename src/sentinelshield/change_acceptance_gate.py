from dataclasses import dataclass


@dataclass(frozen=True)
class ChangeAcceptanceGateInput:
    diff_status: str
    risk_status: str
    validation_status: str


@dataclass(frozen=True)
class ChangeAcceptanceGateResult:
    accepted: bool
    status: str
    reasons: tuple[str, ...]


def evaluate_change_acceptance(
    request: ChangeAcceptanceGateInput,
) -> ChangeAcceptanceGateResult:
    if not isinstance(request, ChangeAcceptanceGateInput):
        raise TypeError("INPUT_MUST_BE_CHANGE_ACCEPTANCE_GATE_INPUT")

    for name, value in (
        ("DIFF_STATUS", request.diff_status),
        ("RISK_STATUS", request.risk_status),
        ("VALIDATION_STATUS", request.validation_status),
    ):
        if not isinstance(value, str):
            raise TypeError(f"{name}_MUST_BE_STRING")
        if not value.strip():
            raise ValueError(f"{name}_MUST_NOT_BE_EMPTY")

    reasons = []

    if request.diff_status != "PASS":
        reasons.append("DIFF_NOT_ACCEPTED")
    if request.risk_status == "FAIL":
        reasons.append("RISK_NOT_ACCEPTED")
    if request.validation_status != "PASS":
        reasons.append("VALIDATION_NOT_ACCEPTED")

    accepted = not reasons
    return ChangeAcceptanceGateResult(
        accepted=accepted,
        status="ACCEPT" if accepted else "REJECT",
        reasons=tuple(reasons),
    )


def change_acceptance_gate(
    request: ChangeAcceptanceGateInput,
) -> ChangeAcceptanceGateResult:
    return evaluate_change_acceptance(request)


__all__ = [
    "ChangeAcceptanceGateInput",
    "ChangeAcceptanceGateResult",
    "evaluate_change_acceptance",
    "change_acceptance_gate",
]
