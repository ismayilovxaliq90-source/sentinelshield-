from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


__test__ = False


@dataclass(frozen=True)
class BlastRadiusReEvaluationInput:
    dependency_tree: Mapping[str, Iterable[str]]
    changed_packages: Iterable[str]
    previous_blast_radius: Iterable[str] = ()


@dataclass(frozen=True)
class BlastRadiusReEvaluationResult:
    affected_packages: tuple[str, ...]
    newly_affected: tuple[str, ...]
    no_longer_affected: tuple[str, ...]
    unchanged_affected: tuple[str, ...]
    status: str

    @property
    def expanded(self) -> bool:
        return bool(self.newly_affected)

    @property
    def reduced(self) -> bool:
        return bool(self.no_longer_affected)

    @property
    def changed(self) -> bool:
        return self.expanded or self.reduced


def _name(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("PACKAGE_NAME_MUST_BE_STRING")
    value = value.strip().lower().replace("_", "-")
    if not value:
        raise ValueError("PACKAGE_NAME_IS_EMPTY")
    return value


def _package_set(values: Iterable[str]) -> set[str]:
    if isinstance(values, (str, bytes)):
        raise TypeError("PACKAGE_COLLECTION_MUST_BE_ITERABLE")
    try:
        return {_name(value) for value in values}
    except TypeError as exc:
        raise TypeError("PACKAGE_COLLECTION_MUST_BE_ITERABLE") from exc


def _tree(tree: Mapping[str, Iterable[str]]) -> dict[str, set[str]]:
    if not isinstance(tree, Mapping):
        raise TypeError("DEPENDENCY_TREE_MUST_BE_MAPPING")

    result: dict[str, set[str]] = {}

    for parent, children in tree.items():
        parent = _name(parent)

        if isinstance(children, (str, bytes)):
            raise TypeError("DEPENDENCY_CHILDREN_MUST_BE_ITERABLE")

        try:
            result[parent] = {_name(child) for child in children}
        except TypeError as exc:
            raise TypeError(
                "DEPENDENCY_CHILDREN_MUST_BE_ITERABLE"
            ) from exc

    return result


def _validate(
    request: BlastRadiusReEvaluationInput,
) -> None:
    if not isinstance(request, BlastRadiusReEvaluationInput):
        raise TypeError(
            "INPUT_MUST_BE_BLAST_RADIUS_RE_EVALUATION_INPUT"
        )

    _tree(request.dependency_tree)
    _package_set(request.changed_packages)
    _package_set(request.previous_blast_radius)


def _reverse_graph(
    tree: dict[str, set[str]],
) -> dict[str, set[str]]:
    reverse: dict[str, set[str]] = {}

    for parent, children in tree.items():
        reverse.setdefault(parent, set())
        for child in children:
            reverse.setdefault(child, set()).add(parent)

    return reverse


def _calculate_affected(
    tree: dict[str, set[str]],
    changed: set[str],
) -> set[str]:
    reverse = _reverse_graph(tree)
    affected = set(changed)
    queue = list(changed)

    while queue:
        current = queue.pop()
        for parent in reverse.get(current, set()):
            if parent not in affected:
                affected.add(parent)
                queue.append(parent)

    return affected


def re_evaluate_blast_radius(
    request: BlastRadiusReEvaluationInput,
) -> BlastRadiusReEvaluationResult:
    _validate(request)

    tree = _tree(request.dependency_tree)
    changed = _package_set(request.changed_packages)
    previous = _package_set(request.previous_blast_radius)

    affected = _calculate_affected(tree, changed)

    newly_affected = affected - previous
    no_longer_affected = previous - affected
    unchanged = affected & previous

    if newly_affected or no_longer_affected:
        status = "CHANGED"
    else:
        status = "UNCHANGED"

    return BlastRadiusReEvaluationResult(
        affected_packages=tuple(sorted(affected)),
        newly_affected=tuple(sorted(newly_affected)),
        no_longer_affected=tuple(sorted(no_longer_affected)),
        unchanged_affected=tuple(sorted(unchanged)),
        status=status,
    )


def blast_radius_re_evaluation(
    request: BlastRadiusReEvaluationInput,
) -> BlastRadiusReEvaluationResult:
    return re_evaluate_blast_radius(request)
