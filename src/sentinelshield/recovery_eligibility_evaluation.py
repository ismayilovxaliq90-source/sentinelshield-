from dataclasses import dataclass

__test__ = False
_VALID={"RESOLUTION","BUILD","TEST","RUNTIME","LOCKFILE","PARTIAL_CHANGE","TIMEOUT","UNKNOWN"}
_BLOCKED={"UNKNOWN","TIMEOUT"}

@dataclass(frozen=True)
class RecoveryEligibilityEvaluationInput:
    category: str
    recoverable: bool
    changes_present: bool = True

@dataclass(frozen=True)
class RecoveryEligibilityEvaluationResult:
    eligible: bool
    category: str
    reason: str
    status: str

def _validate(r):
    if not isinstance(r,RecoveryEligibilityEvaluationInput):
        raise TypeError("INPUT_MUST_BE_RECOVERY_ELIGIBILITY_EVALUATION_INPUT")
    if not isinstance(r.category,str):
        raise TypeError("CATEGORY_MUST_BE_STRING")
    if not isinstance(r.recoverable,bool):
        raise TypeError("RECOVERABLE_MUST_BE_BOOL")
    if not isinstance(r.changes_present,bool):
        raise TypeError("CHANGES_PRESENT_MUST_BE_BOOL")
    c=r.category.strip().upper()
    if not c:
        raise ValueError("CATEGORY_MUST_NOT_BE_EMPTY")
    if c not in _VALID:
        raise ValueError("INVALID_FAILURE_CATEGORY")
    return r

def evaluate_recovery_eligibility(r):
    r=_validate(r)
    c=r.category.strip().upper()
    if not r.changes_present:
        eligible=False
        reason="NO_CHANGES_PRESENT"
    elif c in _BLOCKED:
        eligible=False
        reason="CATEGORY_NOT_ELIGIBLE_FOR_RECOVERY"
    elif not r.recoverable:
        eligible=False
        reason="FAILURE_MARKED_NON_RECOVERABLE"
    else:
        eligible=True
        reason="RECOVERY_ELIGIBLE"
    return RecoveryEligibilityEvaluationResult(
        eligible=eligible, category=c, reason=reason, status="PASS"
    )

def recovery_eligibility_evaluation(r):
    return evaluate_recovery_eligibility(r)

recovery_eligibility_evaluation.__test__=False
