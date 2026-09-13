from dataclasses import dataclass
from pathlib import Path

__test__ = False


@dataclass(frozen=True)
class TestDiscoveryInput:
    project_root: str
    test_directories: tuple[str, ...] = ("tests", "test")
    ignored_directories: tuple[str, ...] = (
        ".git", ".venv", "venv", "node_modules",
        "__pycache__", ".pytest_cache", "build", "dist"
    )


@dataclass(frozen=True)
class TestDiscoveryResult:
    test_files: tuple[str, ...]
    test_directories: tuple[str, ...]
    count: int
    status: str


def discover_tests(request: TestDiscoveryInput) -> TestDiscoveryResult:
    if not isinstance(request, TestDiscoveryInput):
        raise TypeError("INPUT_MUST_BE_TEST_DISCOVERY_INPUT")
    if not isinstance(request.project_root, str) or not request.project_root.strip():
        raise ValueError("PROJECT_ROOT_MUST_BE_NON_EMPTY_STRING")
    if "\x00" in request.project_root:
        raise ValueError("PROJECT_ROOT_CONTAINS_NULL_CHARACTER")

    root = Path(request.project_root).expanduser()
    if not root.exists():
        raise FileNotFoundError("PROJECT_ROOT_NOT_FOUND")
    if not root.is_dir():
        raise NotADirectoryError("PROJECT_ROOT_MUST_BE_DIRECTORY")

    dirs = set()
    ignored = set(request.ignored_directories)
    patterns = ("test_*.py", "*_test.py", "*.test.js", "*.test.ts",
                "*.spec.js", "*.spec.ts", "*.test.jsx", "*.test.tsx",
                "*.spec.jsx", "*.spec.tsx")

    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in ignored for part in rel.parts):
            continue
        if any(part in request.test_directories for part in rel.parts[:-1]):
            files.append(rel.as_posix())
            dirs.add(rel.parent.as_posix())
            continue
        if any(path.match(p) for p in patterns):
            files.append(rel.as_posix())
            dirs.add(rel.parent.as_posix())

    files = tuple(sorted(set(files)))
    directories = tuple(sorted(dirs))
    return TestDiscoveryResult(
        test_files=files,
        test_directories=directories,
        count=len(files),
        status="FOUND" if files else "NOT_FOUND",
    )


def test_discovery(request: TestDiscoveryInput) -> TestDiscoveryResult:
    return discover_tests(request)


__all__ = [
    "TestDiscoveryInput",
    "TestDiscoveryResult",
    "discover_tests",
    "test_discovery",
]
