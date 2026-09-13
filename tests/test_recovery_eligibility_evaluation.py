import pytest
from sentinelshield.recovery_eligibility_evaluation import *

def test_eligible():
    r=evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("BUILD",True))
    assert (r.eligible,r.reason)==(True,"RECOVERY_ELIGIBLE")
def test_resolution():
    assert evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("RESOLUTION",True)).eligible
def test_nonrecoverable():
    r=evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("BUILD",False))
    assert (r.eligible,r.reason)==(False,"FAILURE_MARKED_NON_RECOVERABLE")
def test_unknown():
    r=evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("UNKNOWN",True))
    assert (r.eligible,r.reason)==(False,"CATEGORY_NOT_ELIGIBLE_FOR_RECOVERY")
def test_timeout():
    assert not evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("TIMEOUT",True)).eligible
def test_no_changes():
    r=evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("BUILD",True,False))
    assert (r.eligible,r.reason)==(False,"NO_CHANGES_PRESENT")
def test_case():
    assert evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput(" build ",True)).category=="BUILD"
def test_wrapper():
    assert recovery_eligibility_evaluation(RecoveryEligibilityEvaluationInput("TEST",True)).eligible
def test_wrong_input():
    with pytest.raises(TypeError): evaluate_recovery_eligibility(None)
def test_bad_category():
    with pytest.raises(ValueError): evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("",True))
def test_bad_bool():
    with pytest.raises(TypeError): evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("BUILD",1))
def test_bad_changes():
    with pytest.raises(TypeError): evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("BUILD",True,1))
def test_result():
    r=evaluate_recovery_eligibility(RecoveryEligibilityEvaluationInput("BUILD",True))
    assert isinstance(r,RecoveryEligibilityEvaluationResult)
    assert r.status=="PASS"
