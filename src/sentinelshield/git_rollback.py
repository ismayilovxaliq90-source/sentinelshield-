from dataclasses import dataclass
import subprocess
from pathlib import Path

__test__ = False

@dataclass(frozen=True)
class GitRollbackInput:
    project_root: Path
    target_commit: str
    allow_rollback: bool = False
    timeout: int = 120

@dataclass(frozen=True)
class GitRollbackResult:
    success: bool
    target_commit: str
    return_code: int
    stdout: str
    stderr: str
    status: str

def _validate(r):
    if not isinstance(r,GitRollbackInput):
        raise TypeError("INPUT_MUST_BE_GIT_ROLLBACK_INPUT")
    if not isinstance(r.project_root,Path):
        raise TypeError("PROJECT_ROOT_MUST_BE_PATH")
    if not isinstance(r.target_commit,str):
        raise TypeError("TARGET_COMMIT_MUST_BE_STRING")
    if not r.target_commit.strip():
        raise ValueError("TARGET_COMMIT_MUST_NOT_BE_EMPTY")
    if not isinstance(r.allow_rollback,bool):
        raise TypeError("ALLOW_ROLLBACK_MUST_BE_BOOL")
    if not isinstance(r.timeout,int) or isinstance(r.timeout,bool):
        raise TypeError("TIMEOUT_MUST_BE_INT")
    if r.timeout<=0:
        raise ValueError("TIMEOUT_MUST_BE_POSITIVE")
    if not r.project_root.exists() or not r.project_root.is_dir():
        raise ValueError("PROJECT_ROOT_MUST_BE_DIRECTORY")
    c=r.target_commit.strip()
    if any(x in c for x in (";","&&","||","|","`","$","\\","\n","\r")):
        raise ValueError("TARGET_COMMIT_CONTAINS_UNSAFE_CHARACTER")
    return r

def git_rollback(r):
    r=_validate(r)
    if not r.allow_rollback:
        return GitRollbackResult(False,r.target_commit.strip(),-1,"",
                                 "ROLLBACK_NOT_EXPLICITLY_ALLOWED","BLOCKED")
    try:
        p=subprocess.run(
            ("git","reset","--hard",r.target_commit.strip()),
            cwd=r.project_root,capture_output=True,text=True,
            timeout=r.timeout,check=False,
        )
    except subprocess.TimeoutExpired as e:
        return GitRollbackResult(False,r.target_commit.strip(),-1,
                                 e.stdout or "",e.stderr or "","TIMEOUT")
    return GitRollbackResult(
        p.returncode==0,r.target_commit.strip(),p.returncode,
        p.stdout,p.stderr,"PASS" if p.returncode==0 else "FAIL",
    )

def execute_git_rollback(r):
    return git_rollback(r)

execute_git_rollback.__test__=False
