from dataclasses import dataclass

__test__ = False
_VALID={"FAIL","ERROR","TIMEOUT"}
_KEYWORDS={
 "COMPILER":("compile","compiler","syntax error","compilation"),
 "DEPENDENCY":("dependency","package","module","not found"),
 "CONFIGURATION":("configuration","config","invalid option","setting"),
 "RESOURCE":("out of memory","disk full","no space","resource"),
 "PERMISSION":("permission denied","access denied"),
}

@dataclass(frozen=True)
class BuildFailureHandlingInput:
    status: str
    message: str = ""

@dataclass(frozen=True)
class BuildFailureHandlingResult:
    category: str
    recoverable: bool
    status: str

def _validate(r):
    if not isinstance(r,BuildFailureHandlingInput):
        raise TypeError("INPUT_MUST_BE_BUILD_FAILURE_HANDLING_INPUT")
    if not isinstance(r.status,str):
        raise TypeError("STATUS_MUST_BE_STRING")
    if not isinstance(r.message,str):
        raise TypeError("MESSAGE_MUST_BE_STRING")
    if not r.status.strip():
        raise ValueError("STATUS_MUST_NOT_BE_EMPTY")
    for n,v in (("STATUS",r.status),("MESSAGE",r.message)):
        if "\x00" in v or any(ord(c)<32 and c not in "\t\n\r" for c in v):
            raise ValueError(f"{n}_CONTAINS_CONTROL_CHARACTER")
    s=r.status.strip().upper()
    if s not in _VALID:
        raise ValueError("INVALID_FAILURE_STATUS")
    return r

def handle_build_failure(r):
    r=_validate(r)
    s=r.status.strip().upper()
    msg=r.message.lower()
    category="TIMEOUT" if s=="TIMEOUT" else "UNKNOWN"
    if s!="TIMEOUT":
        for cat,words in _KEYWORDS.items():
            if any(w in msg for w in words):
                category=cat
                break
    return BuildFailureHandlingResult(
        category=category,
        recoverable=category in {"COMPILER","DEPENDENCY","CONFIGURATION"},
        status="PASS",
    )

def build_failure_handling(r):
    return handle_build_failure(r)

build_failure_handling.__test__=False
