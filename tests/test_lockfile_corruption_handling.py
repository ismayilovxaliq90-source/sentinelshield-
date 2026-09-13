import pytest
from sentinelshield.lockfile_corruption_handling import *

def test_corrupted():
    r=handle_lockfile_corruption(LockfileCorruptionHandlingInput("FAIL","lockfile corrupted","x.lock"))
    assert (r.corrupted,r.recoverable,r.category)==(True,True,"CORRUPTED")
def test_malformed():
    assert handle_lockfile_corruption(LockfileCorruptionHandlingInput("ERROR","malformed lock file")).category=="CORRUPTED"
def test_invalid():
    assert handle_lockfile_corruption(LockfileCorruptionHandlingInput("FAIL","invalid lockfile")).corrupted
def test_checksum():
    assert handle_lockfile_corruption(LockfileCorruptionHandlingInput("ERROR","checksum mismatch")).corrupted
def test_parse():
    assert handle_lockfile_corruption(LockfileCorruptionHandlingInput("FAIL","parse error")).corrupted
def test_timeout():
    r=handle_lockfile_corruption(LockfileCorruptionHandlingInput("TIMEOUT"))
    assert (r.category,r.corrupted)==("TIMEOUT",False)
def test_unknown():
    r=handle_lockfile_corruption(LockfileCorruptionHandlingInput("ERROR","build failed"))
    assert (r.category,r.corrupted)==("UNKNOWN",False)
def test_wrapper():
    assert lockfile_corruption_handling(LockfileCorruptionHandlingInput("FAIL","corrupted")).corrupted
def test_wrong_input():
    with pytest.raises(TypeError): handle_lockfile_corruption(None)
def test_bad_status():
    with pytest.raises(ValueError): handle_lockfile_corruption(LockfileCorruptionHandlingInput(""))
def test_bad_message():
    with pytest.raises(TypeError): handle_lockfile_corruption(LockfileCorruptionHandlingInput("FAIL",1))
def test_result():
    r=handle_lockfile_corruption(LockfileCorruptionHandlingInput("FAIL","corrupted","a.lock"))
    assert isinstance(r,LockfileCorruptionHandlingResult)
    assert r.lockfile=="a.lock"
