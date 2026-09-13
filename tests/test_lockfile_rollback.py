import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch
from sentinelshield.lockfile_rollback import *

def inp(**kw):
    d={"project_root":Path("."),
       "lockfile":Path("poetry.lock"),
       "target_commit":"HEAD"}
    d.update(kw)
    return LockfileRollbackInput(**d)

def test_blocked():
    assert lockfile_rollback(inp()).status=="BLOCKED"

def test_success():
    class P: returncode=0; stdout="ok"; stderr=""
    with patch("sentinelshield.lockfile_rollback.subprocess.run",return_value=P()):
        r=lockfile_rollback(inp(allow_rollback=True))
    assert r.success and r.status=="PASS"

def test_failure():
    class P: returncode=1; stdout=""; stderr="bad"
    with patch("sentinelshield.lockfile_rollback.subprocess.run",return_value=P()):
        r=lockfile_rollback(inp(allow_rollback=True))
    assert not r.success and r.status=="FAIL"

def test_timeout():
    with patch("sentinelshield.lockfile_rollback.subprocess.run",
               side_effect=subprocess.TimeoutExpired("git",1)):
        r=lockfile_rollback(inp(allow_rollback=True))
    assert r.status=="TIMEOUT"

def test_wrapper():
    assert execute_lockfile_rollback(inp()).status=="BLOCKED"

def test_wrong_input():
    with pytest.raises(TypeError): lockfile_rollback(None)

def test_bad_commit():
    with pytest.raises(ValueError): lockfile_rollback(inp(target_commit=""))

def test_unsafe_commit():
    with pytest.raises(ValueError): lockfile_rollback(inp(target_commit="HEAD;rm"))

def test_bad_permission():
    with pytest.raises(TypeError): lockfile_rollback(inp(allow_rollback=1))

def test_bad_timeout():
    with pytest.raises(ValueError): lockfile_rollback(inp(timeout=0))

def test_bad_root():
    with pytest.raises(ValueError):
        lockfile_rollback(inp(project_root=Path("/no/such/path")))

def test_lockfile_outside():
    with pytest.raises(ValueError):
        lockfile_rollback(inp(lockfile=Path("/tmp/x.lock")))

def test_result():
    r=lockfile_rollback(inp())
    assert isinstance(r,LockfileRollbackResult)
    assert r.lockfile=="poetry.lock"
