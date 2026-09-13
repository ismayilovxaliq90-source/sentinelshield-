from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Iterable


__test__ = False


@dataclass(frozen=True, order=True)
class DependencyTreeEdge:
    parent: str
    child: str


@dataclass(frozen=True)
class DependencyTreeComparisonInput:
    before_tree: Mapping[str, Iterable[str]]
    after_tree: Mapping[str, Iterable[str]]


@dataclass(frozen=True)
class DependencyTreeComparisonResult:
    before_edges: tuple[DependencyTreeEdge, ...]
    after_edges: tuple[DependencyTreeEdge, ...]
    added_edges: tuple[DependencyTreeEdge, ...]
    removed_edges: tuple[DependencyTreeEdge, ...]
    changed_nodes: tuple[str, ...]
    status: str

    @property
    def has_change(self) -> bool:
        return bool(self.added_edges or self.removed_edges)

    @property
    def unchanged(self) -> bool:
        return not self.has_change

    @property
    def added_dependencies(self) -> tuple[DependencyTreeEdge, ...]:
        return self.added_edges

    @property
    def removed_dependencies(self) -> tuple[DependencyTreeEdge, ...]:
        return self.removed_edges


def _normalize_name(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("PACKAGE_NAME_MUST_BE_STRING")

    value = name.strip().lower().replace("_", "-")

    if not value:
        raise ValueError("PACKAGE_NAME_IS_EMPTY")

    return value


def _normalize_tree(
    tree: Mapping[str, Iterable[str]],
) -> tuple[DependencyTreeEdge, ...]:
    if not isinstance(tree, Mapping):
        raise TypeError("DEPENDENCY_TREE_MUST_BE_MAPPING")

    edges: set[DependencyTreeEdge] = set()

    for raw_parent, raw_children in tree.items():
        parent = _normalize_name(raw_parent)

        if isinstance(raw_children, (str, bytes)):
            raise TypeError("DEPENDENCY_CHILDREN_MUST_BE_ITERABLE")

        try:
            children = iter(raw_children)
        except TypeError as exc:
            raise TypeError(
                "DEPENDENCY_CHILDREN_MUST_BE_ITERABLE"
            ) from exc

        for raw_child in children:
            child = _normalize_name(raw_child)

            if parent == child:
                raise ValueError(
                    "SELF_DEPENDENCY_EDGE_IS_NOT_ALLOWED"
                )

            edges.add(
                DependencyTreeEdge(
                    parent=parent,
                    child=child,
                )
            )

    return tuple(sorted(edges))


def _validate_input(
    request: DependencyTreeComparisonInput,
) -> DependencyTreeComparisonInput:
    if not isinstance(
        request,
        DependencyTreeComparisonInput,
    ):
        raise TypeError(
            "INPUT_MUST_BE_DEPENDENCY_TREE_COMPARISON_INPUT"
        )

    # Force complete validation before comparison.
    _normalize_tree(request.before_tree)
    _normalize_tree(request.after_tree)

    return request


def compare_dependency_trees(
    request: DependencyTreeComparisonInput,
) -> DependencyTreeComparisonResult:
    request = _validate_input(request)

    before_edges = _normalize_tree(request.before_tree)
    after_edges = _normalize_tree(request.after_tree)

    before_set = set(before_edges)
    after_set = set(after_edges)

    added_edges = tuple(sorted(after_set - before_set))
    removed_edges = tuple(sorted(before_set - after_set))

    changed_nodes = tuple(
        sorted(
            {
                edge.parent
                for edge in added_edges + removed_edges
            }
            |
            {
                edge.child
                for edge in added_edges + removed_edges
            }
        )
    )

    if added_edges or removed_edges:
        status = "CHANGED"
    else:
        status = "UNCHANGED"

    return DependencyTreeComparisonResult(
        before_edges=before_edges,
        after_edges=after_edges,
        added_edges=added_edges,
        removed_edges=removed_edges,
        changed_nodes=changed_nodes,
        status=status,
    )


def dependency_tree_comparison(
    request: DependencyTreeComparisonInput,
) -> DependencyTreeComparisonResult:
    return compare_dependency_trees(request)
