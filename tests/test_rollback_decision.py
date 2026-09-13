import pytest
from sentinelshield.rollback_decision import *

def test_build_requires():
    r=decide_rollback(RollbackDecisionInput("BUILD",True,True))
    assert (r.rollback_required,r.reason)==(True,"BLOCKING_FAILURE_REQUIRES_ROLLBACK")
def test_test_requires():
    assert decide_rollback(RollbackDecisionInput("TEST",True,True)).rollback_required
def test_runtime_requires():
    assert decide_rollback(RollbackDecisionInput("RUNTIME",True,True)).rollback_required
def test_lockfile_requires():
    assert decide_rollback(RollbackDecisionInput("LOCKFILE",True,True)).rollback_required
def test_partial_requires():
    assert decide_rollback(RollbackDecisionInput("PARTIAL_CHANGE",True,True)).rollback_required
def test_not_eligible():
    r=decide_rollback(RollbackDecisionInput("BUILD",False,True))
    assert r.reason=="RECOVERY_NOT_ELIGIBLE"
def test_no_changes():
    r=decide_rollback(RollbackDecisionInput("BUILD",True,False))
    assert (r.rollback_required,r.reason)==(False,"NO_CHANGES_PRESENT")
def test_validation_passed():
    r=decide_rollback(RollbackDecisionInput("BUILD",True,True,True))
    assert (r.rollback_required,r.reason)==(False,"VALIDATION_PASSED")
def test_case():
    assert decide_rollback(RollbackDecisionInput(" build ",True,True)).category=="BUILD"
def test_wrapper():
    assert rollback_decision(RollbackDecisionInput("TEST",True,True)).rollback_required
def test_wrong_input():
    with pytest.raises(TypeError): decide_rollback(None)
def test_bad_category():
    with pytest.raises(ValueError): decide_rollback(RollbackDecisionInput("",True,True))
def test_bad_bool():
    with pytest.raises(TypeError): decide_rollback(RollbackDecisionInput("BUILD",1,True))
def test_result():
    r=decide_rollback(RollbackDecisionInput("BUILD",True,True))
    assert isinstance(r,RollbackDecisionResult)
    assert r.status=="PASS"
