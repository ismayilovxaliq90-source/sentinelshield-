from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable, Mapping


# This source module is not a pytest test module.
__test__ = False


@dataclass(frozen=True)
class TestImpact:
    test: str
    impact: str
    affected: bool
    reason: str
    changed_files: tuple[str, ...]


@dataclass(frozen=True)
class TestImpactAnalysisInput:
    changed_files: Iterable[str]
    test_files: Iterable[str]
    test_dependencies: Mapping[str, Iterable[str]]


@dataclass(frozen=True)
class TestImpactAnalysisResult:
    impacts: tuple[TestImpact, ...]

    @property
    def affected(self) -> tuple[TestImpact, ...]:
        return tuple(item for item in self.impacts if item.affected)

    @property
    def unaffected(self) -> tuple[TestImpact, ...]:
        return tuple(
            item for item in self.impacts
            if not item.affected
        )


def _normalize_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value


def _validate_input(
    request: TestImpactAnalysisInput,
) -> TestImpactAnalysisInput:
    if not isinstance(request, TestImpactAnalysisInput):
        raise TypeError(
            "INPUT_MUST_BE_TEST_IMPACT_ANALYSIS_INPUT"
        )

    if isinstance(request.changed_files, (str, bytes)):
        raise TypeError("CHANGED_FILES_MUST_BE_ITERABLE")

    if isinstance(request.test_files, (str, bytes)):
        raise TypeError("TEST_FILES_MUST_BE_ITERABLE")

    if not isinstance(request.test_dependencies, Mapping):
        raise TypeError("TEST_DEPENDENCIES_MUST_BE_MAPPING")

    changed = []
    for item in request.changed_files:
        if not isinstance(item, str):
            raise TypeError("CHANGED_FILE_MUST_BE_STRING")

        normalized = _normalize_path(item)

        if not normalized:
            raise ValueError("CHANGED_FILE_IS_EMPTY")

        changed.append(normalized)

    tests = []
    for item in request.test_files:
        if not isinstance(item, str):
            raise TypeError("TEST_FILE_MUST_BE_STRING")

        normalized = _normalize_path(item)

        if not normalized:
            raise ValueError("TEST_FILE_IS_EMPTY")

        tests.append(normalized)

    dependencies: dict[str, tuple[str, ...]] = {}

    for test, files in request.test_dependencies.items():
        if not isinstance(test, str):
            raise TypeError("TEST_DEPENDENCY_KEY_MUST_BE_STRING")

        normalized_test = _normalize_path(test)

        if not normalized_test:
            raise ValueError("TEST_DEPENDENCY_KEY_IS_EMPTY")

        if isinstance(files, (str, bytes)):
            raise TypeError(
                "TEST_DEPENDENCY_FILES_MUST_BE_ITERABLE"
            )

        normalized_files = []

        for file in files:
            if not isinstance(file, str):
                raise TypeError(
                    "TEST_DEPENDENCY_FILE_MUST_BE_STRING"
                )

            normalized_file = _normalize_path(file)

            if not normalized_file:
                raise ValueError(
                    "TEST_DEPENDENCY_FILE_IS_EMPTY"
                )

            normalized_files.append(normalized_file)

        dependencies[normalized_test] = tuple(
            dict.fromkeys(normalized_files)
        )

    return TestImpactAnalysisInput(
        changed_files=tuple(dict.fromkeys(changed)),
        test_files=tuple(dict.fromkeys(tests)),
        test_dependencies=dependencies,
    )


def _candidate_test_paths(test: str) -> set[str]:
    path = PurePosixPath(test)
    name = path.name

    candidates = {test}

    if name.startswith("test_"):
        candidates.add(name[5:])
    elif name.endswith("_test.py"):
        candidates.add(name[:-8] + ".py")

    return candidates


def _source_candidates(changed_file: str) -> set[str]:
    path = PurePosixPath(changed_file)

    candidates = {changed_file}

    if path.parts and path.parts[0] == "src":
        relative = PurePosixPath(*path.parts[1:])
        candidates.add(str(relative))

    if path.parts and path.parts[0] == "tests":
        relative = PurePosixPath(*path.parts[1:])
        candidates.add(str(relative))

    return candidates


def _name_related(
    test: str,
    changed_file: str,
) -> bool:
    test_path = PurePosixPath(test)
    changed_path = PurePosixPath(changed_file)

    test_stem = test_path.stem
    changed_stem = changed_path.stem

    if test_stem == f"test_{changed_stem}":
        return True

    if test_stem == f"{changed_stem}_test":
        return True

    test_parts = test_path.parts
    changed_parts = changed_path.parts

    if (
        len(test_parts) >= 2
        and len(changed_parts) >= 2
        and test_parts[-2] == changed_parts[-2]
        and (
            test_stem == f"test_{changed_stem}"
            or test_stem == f"{changed_stem}_test"
        )
    ):
        return True

    return False


def _matching_dependency(
    test: str,
    changed_file: str,
    dependencies: Mapping[str, Iterable[str]],
) -> bool:
    declared = dependencies.get(test)

    if declared is None:
        return False

    changed_candidates = _source_candidates(changed_file)

    return bool(
        set(declared).intersection(changed_candidates)
    )


def _analyze_test(
    test: str,
    changed_files: tuple[str, ...],
    dependencies: Mapping[str, Iterable[str]],
) -> TestImpact:
    if not changed_files:
        return TestImpact(
            test=test,
            impact="NONE",
            affected=False,
            reason="NO_CHANGED_FILES",
            changed_files=(),
        )

    directly_changed = tuple(
        file
        for file in changed_files
        if file == test
    )

    if directly_changed:
        return TestImpact(
            test=test,
            impact="DIRECT",
            affected=True,
            reason="TEST_FILE_CHANGED",
            changed_files=directly_changed,
        )

    dependency_matches = tuple(
        file
        for file in changed_files
        if _matching_dependency(
            test,
            file,
            dependencies,
        )
    )

    if dependency_matches:
        return TestImpact(
            test=test,
            impact="DIRECT",
            affected=True,
            reason="DECLARED_TEST_DEPENDENCY_CHANGED",
            changed_files=dependency_matches,
        )

    related = tuple(
        file
        for file in changed_files
        if _name_related(test, file)
    )

    if related:
        return TestImpact(
            test=test,
            impact="DIRECT",
            affected=True,
            reason="RELATED_SOURCE_CHANGED",
            changed_files=related,
        )

    return TestImpact(
        test=test,
        impact="NONE",
        affected=False,
        reason="TEST_UNAFFECTED",
        changed_files=(),
    )


def analyze_test_impact(
    request: TestImpactAnalysisInput,
) -> TestImpactAnalysisResult:
    request = _validate_input(request)

    tests = tuple(
        sorted(
            dict.fromkeys(
                _normalize_path(test)
                for test in request.test_files
            )
        )
    )

    impacts = tuple(
        _analyze_test(
            test,
            tuple(request.changed_files),
            request.test_dependencies,
        )
        for test in tests
    )

    return TestImpactAnalysisResult(
        impacts=impacts,
    )


def test_impact_analysis(
    request: TestImpactAnalysisInput,
) -> TestImpactAnalysisResult:
    return analyze_test_impact(request)
