from dataclasses import dataclass
from pathlib import Path
import subprocess

__test__ = False

@dataclass(frozen=True)
class LockfileRollbackInput:
    project_root: Path
    lockfile: Path
    target_commit: str
    allow_rollback: bool = False
    timeout: int = 120

@dataclass(frozen=True)
class LockfileRollbackResult:
    success: bool
    lockfile: str
    target_commit: str
    return_code: int
    stdout: str
    stderr: str
    status: str

def _validate(r):
    if not isinstance(r,LockfileRollbackInput):
        raise TypeError("INPUT_MUST_BE_LOCKFILE_ROLLBACK_INPUT")
    if not isinstance(r.project_root,Path):
        raise TypeError("PROJECT_ROOT_MUST_BE_PATH")
    if not isinstance(r.lockfile,Path):
        raise TypeError("LOCKFILE_MUST_BE_PATH")
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
    try:
        rel=r.lockfile.resolve().relative_to(r.project_root.resolve())
    except ValueError:
        raise ValueError("LOCKFILE_MUST_BE_INSIDE_PROJECT_ROOT")
    if not r.lockfile.name:
        raise ValueError("LOCKFILE_MUST_NOT_BE_EMPTY")
    c=r.target_commit.strip()
    if any(x in c for x in (";","&&","||","|","`","$","\\","\n","\r")):
        raise ValueError("TARGET_COMMIT_CONTAINS_UNSAFE_CHARACTER")
    return r,str(rel)

def lockfile_rollback(r):
    r,rel=_validate(r)
    if not r.allow_rollback:
        return LockfileRollbackResult(False,rel,r.target_commit.strip(),-1,"",
                                      "ROLLBACK_NOT_EXPLICITLY_ALLOWED","BLOCKED")
    try:
        p=subprocess.run(
            ("git","checkout",r.target_commit.strip(),"--",rel),
            cwd=r.project_root,capture_output=True,text=True,
            timeout=r.timeout,check=False,
        )
    except subprocess.TimeoutExpired as e:
        return LockfileRollbackResult(False,rel,r.target_commit.strip(),-1,
                                      e.stdout or "",e.stderr or "","TIMEOUT")
    return LockfileRollbackResult(
        p.returncode==0,rel,r.target_commit.strip(),p.returncode,
        p.stdout,p.stderr,"PASS" if p.returncode==0 else "FAIL",
    )

def execute_lockfile_rollback(r):
    return lockfile_rollback(r)

execute_lockfile_rollback.__test__=False
