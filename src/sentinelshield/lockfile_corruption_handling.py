from dataclasses import dataclass

__test__ = False
_VALID={"FAIL","ERROR","TIMEOUT"}
_KEYWORDS=("corrupt","corrupted","invalid","malformed","parse error","parse failed","checksum","integrity")

@dataclass(frozen=True)
class LockfileCorruptionHandlingInput:
    status: str
    message: str = ""
    lockfile: str = ""

@dataclass(frozen=True)
class LockfileCorruptionHandlingResult:
    corrupted: bool
    recoverable: bool
    lockfile: str
    category: str
    status: str

def _validate(r):
    if not isinstance(r,LockfileCorruptionHandlingInput):
        raise TypeError("INPUT_MUST_BE_LOCKFILE_CORRUPTION_HANDLING_INPUT")
    for name in ("status","message","lockfile"):
        v=getattr(r,name)
        if not isinstance(v,str):
            raise TypeError(f"{name.upper()}_MUST_BE_STRING")
        if "\x00" in v or any(ord(c)<32 and c not in "\t\n\r" for c in v):
            raise ValueError(f"{name.upper()}_CONTAINS_CONTROL_CHARACTER")
    if not r.status.strip():
        raise ValueError("STATUS_MUST_NOT_BE_EMPTY")
    if r.status.strip().upper() not in _VALID:
        raise ValueError("INVALID_FAILURE_STATUS")
    return r

def handle_lockfile_corruption(r):
    r=_validate(r)
    s=r.status.strip().upper()
    msg=r.message.lower()
    corrupted=s in {"FAIL","ERROR"} and any(k in msg for k in _KEYWORDS)
    if s=="TIMEOUT":
        category="TIMEOUT"
    elif corrupted:
        category="CORRUPTED"
    else:
        category="UNKNOWN"
    return LockfileCorruptionHandlingResult(
        corrupted=corrupted,
        recoverable=corrupted,
        lockfile=r.lockfile.strip(),
        category=category,
        status="PASS",
    )

def lockfile_corruption_handling(r):
    return handle_lockfile_corruption(r)

lockfile_corruption_handling.__test__=False
