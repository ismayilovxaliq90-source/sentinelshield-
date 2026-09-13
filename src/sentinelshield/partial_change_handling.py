from dataclasses import dataclass

__test__ = False
_VALID={"PASS","FAIL","ERROR","TIMEOUT"}
_KEYWORDS=("partial","partially","incomplete","half-applied","half applied","interrupted","unfinished")

@dataclass(frozen=True)
class PartialChangeHandlingInput:
    status: str
    message: str = ""
    expected_files: tuple[str,...] = ()
    changed_files: tuple[str,...] = ()

@dataclass(frozen=True)
class PartialChangeHandlingResult:
    partial: bool
    recoverable: bool
    missing_files: tuple[str,...]
    unexpected_files: tuple[str,...]
    category: str
    status: str

def _validate(r):
    if not isinstance(r,PartialChangeHandlingInput):
        raise TypeError("INPUT_MUST_BE_PARTIAL_CHANGE_HANDLING_INPUT")
    if not isinstance(r.status,str) or not isinstance(r.message,str):
        raise TypeError("STATUS_AND_MESSAGE_MUST_BE_STRING")
    if not r.status.strip():
        raise ValueError("STATUS_MUST_NOT_BE_EMPTY")
    if r.status.strip().upper() not in _VALID:
        raise ValueError("INVALID_FAILURE_STATUS")
    for name,v in (("EXPECTED_FILES",r.expected_files),("CHANGED_FILES",r.changed_files)):
        if not isinstance(v,tuple):
            raise TypeError(f"{name}_MUST_BE_TUPLE")
        for x in v:
            if not isinstance(x,str) or not x.strip():
                raise TypeError(f"{name}_ITEMS_MUST_BE_NONEMPTY_STRING")
            if "\x00" in x:
                raise ValueError(f"{name}_CONTAINS_NULL_CHARACTER")
    return r

def handle_partial_change(r):
    r=_validate(r)
    expected=set(r.expected_files)
    changed=set(r.changed_files)
    missing=tuple(sorted(expected-changed))
    unexpected=tuple(sorted(changed-expected))
    msg=r.message.lower()
    partial=(
        r.status.strip().upper() in {"FAIL","ERROR"} and
        (any(k in msg for k in _KEYWORDS) or bool(missing and changed))
    )
    category="PARTIAL_CHANGE" if partial else ("TIMEOUT" if r.status.strip().upper()=="TIMEOUT" else "UNKNOWN")
    return PartialChangeHandlingResult(
        partial=partial,
        recoverable=partial,
        missing_files=missing,
        unexpected_files=unexpected,
        category=category,
        status="PASS",
    )

def partial_change_handling(r):
    return handle_partial_change(r)

partial_change_handling.__test__=False
