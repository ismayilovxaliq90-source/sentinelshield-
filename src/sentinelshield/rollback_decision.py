from dataclasses import dataclass

__test__ = False
_VALID={"RESOLUTION","BUILD","TEST","RUNTIME","LOCKFILE","PARTIAL_CHANGE","TIMEOUT","UNKNOWN"}
_BLOCKING={"BUILD","TEST","RUNTIME","LOCKFILE","PARTIAL_CHANGE","TIMEOUT","UNKNOWN"}

@dataclass(frozen=True)
class RollbackDecisionInput:
    failure_category: str
    recovery_eligible: bool
    changes_present: bool
    validation_passed: bool = False

@dataclass(frozen=True)
class RollbackDecisionResult:
    rollback_required: bool
    category: str
    reason: str
    status: str

def _validate(r):
    if not isinstance(r,RollbackDecisionInput):
        raise TypeError("INPUT_MUST_BE_ROLLBACK_DECISION_INPUT")
    if not isinstance(r.failure_category,str):
        raise TypeError("FAILURE_CATEGORY_MUST_BE_STRING")
    for n,v in (("RECOVERY_ELIGIBLE",r.recovery_eligible),
                ("CHANGES_PRESENT",r.changes_present),
                ("VALIDATION_PASSED",r.validation_passed)):
        if not isinstance(v,bool):
            raise TypeError(f"{n}_MUST_BE_BOOL")
    c=r.failure_category.strip().upper()
    if not c:
        raise ValueError("FAILURE_CATEGORY_MUST_NOT_BE_EMPTY")
    if c not in _VALID:
        raise ValueError("INVALID_FAILURE_CATEGORY")
    return r

def decide_rollback(r):
    r=_validate(r)
    c=r.failure_category.strip().upper()
    if not r.changes_present:
        required=False
        reason="NO_CHANGES_PRESENT"
    elif r.validation_passed:
        required=False
        reason="VALIDATION_PASSED"
    elif not r.recovery_eligible:
        required=True
        reason="RECOVERY_NOT_ELIGIBLE"
    elif c in _BLOCKING:
        required=True
        reason="BLOCKING_FAILURE_REQUIRES_ROLLBACK"
    else:
        required=False
        reason="ROLLBACK_NOT_REQUIRED"
    return RollbackDecisionResult(required,c,reason,"PASS")

def rollback_decision(r):
    return decide_rollback(r)

rollback_decision.__test__=False
