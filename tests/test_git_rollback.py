import pytest
from pathlib import Path
from unittest.mock import patch
from sentinelshield.git_rollback import *

def root():
    return Path(".")

def test_blocked_without_permission():
    r=git_rollback(GitRollbackInput(root(),"HEAD"))
    assert r.status=="BLOCKED" and not r.success

def test_success():
    class P: returncode=0; stdout="ok"; stderr=""
    with patch("sentinelshield.git_rollback.subprocess.run",return_value=P()):
        r=git_rollback(GitRollbackInput(root(),"abc123",True))
    assert r.success and r.status=="PASS"

def test_failure():
    class P: returncode=1; stdout=""; stderr="bad"
    with patch("sentinelshield.git_rollback.subprocess.run",return_value=P()):
        r=git_rollback(GitRollbackInput(root(),"abc123",True))
    assert not r.success and r.status=="FAIL"

def test_timeout():
    with patch("sentinelshield.git_rollback.subprocess.run",side_effect=__import__("subprocess").TimeoutExpired("git",1)):
        r=git_rollback(GitRollbackInput(root(),"abc123",True))
    assert r.status=="TIMEOUT"

def test_wrapper():
    r=execute_git_rollback(GitRollbackInput(root(),"HEAD"))
    assert r.status=="BLOCKED"

def test_wrong_input():
    with pytest.raises(TypeError): git_rollback(None)

def test_bad_commit():
    with pytest.raises(ValueError): git_rollback(GitRollbackInput(root(),""))

def test_unsafe_commit():
    with pytest.raises(ValueError): git_rollback(GitRollbackInput(root(),"HEAD;rm -rf"))

def test_bad_permission():
    with pytest.raises(TypeError): git_rollback(GitRollbackInput(root(),"HEAD",1))

def test_bad_timeout():
    with pytest.raises(ValueError): git_rollback(GitRollbackInput(root(),"HEAD",False,0))

def test_bad_root():
    with pytest.raises(ValueError): git_rollback(GitRollbackInput(Path("/no/such/path"),"HEAD"))

def test_result():
    r=git_rollback(GitRollbackInput(root(),"HEAD"))
    assert isinstance(r,GitRollbackResult)
    assert r.target_commit=="HEAD"
