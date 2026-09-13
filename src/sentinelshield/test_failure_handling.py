from dataclasses import dataclass

__test__ = False
_VALID={"FAIL","ERROR","TIMEOUT"}
_KEYWORDS={
 "ASSERTION":("assertion","assert ","expected","actual"),
 "COLLECTION":("collection error","collecting","fixture","fixture error"),
 "IMPORT":("import error","modulenotfound","no module named","cannot import"),
 "SETUP":("setup failed","setup error","teardown failed","teardown error"),
 "ENVIRONMENT":("environment","permission denied","file not found","no such file"),
}

@dataclass(frozen=True)
class TestFailureHandlingInput:
    status: str
    message: str = ""

@dataclass(frozen=True)
class TestFailureHandlingResult:
    category: str
    recoverable: bool
    status: str

def _validate(r):
    if not isinstance(r,TestFailureHandlingInput):
        raise TypeError("INPUT_MUST_BE_TEST_FAILURE_HANDLING_INPUT")
    if not isinstance(r.status,str):
        raise TypeError("STATUS_MUST_BE_STRING")
    if not isinstance(r.message,str):
        raise TypeError("MESSAGE_MUST_BE_STRING")
    if not r.status.strip():
        raise ValueError("STATUS_MUST_NOT_BE_EMPTY")
    for n,v in (("STATUS",r.status),("MESSAGE",r.message)):
        if "\x00" in v or any(ord(c)<32 and c not in "\t\n\r" for c in v):
            raise ValueError(f"{n}_CONTAINS_CONTROL_CHARACTER")
    if r.status.strip().upper() not in _VALID:
        raise ValueError("INVALID_FAILURE_STATUS")
    return r

def handle_test_failure(r):
    r=_validate(r)
    s=r.status.strip().upper()
    msg=r.message.lower()
    category="TIMEOUT" if s=="TIMEOUT" else "UNKNOWN"
    if s!="TIMEOUT":
        for cat,words in _KEYWORDS.items():
            if any(w in msg for w in words):
                category=cat
                break
    return TestFailureHandlingResult(
        category=category,
        recoverable=category in {"ASSERTION","COLLECTION","IMPORT","SETUP"},
        status="PASS",
    )

def test_failure_handling(r):
    return handle_test_failure(r)

test_failure_handling.__test__=False
