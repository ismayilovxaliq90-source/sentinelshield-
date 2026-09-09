from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True)
class CircularDependencyResult:
    cycles: tuple[tuple[str, ...], ...]
    has_cycles: bool
    checked: bool
    status: str


def detect_circular_dependencies(
    graph: Mapping[str, Iterable[str]] | None,
) -> CircularDependencyResult:
    """
    Detect directed dependency cycles using DFS.

    Read-only operation:
    - does not modify the supplied graph
    - does not execute project code
    - does not install packages
    - does not invoke package managers
    """

    if graph is None:
        return CircularDependencyResult(
            cycles=(),
            has_cycles=False,
            checked=False,
            status="GRAPH_IS_NONE",
        )

    if not isinstance(graph, Mapping):
        return CircularDependencyResult(
            cycles=(),
            has_cycles=False,
            checked=False,
            status="UNSUPPORTED_GRAPH_TYPE",
        )

    normalized: dict[str, tuple[str, ...]] = {}

    try:
        for raw_node, raw_children in graph.items():
            if not isinstance(raw_node, str) or not raw_node.strip():
                return CircularDependencyResult(
                    cycles=(),
                    has_cycles=False,
                    checked=False,
                    status="INVALID_NODE_NAME",
                )

            if isinstance(raw_children, (str, bytes)):
                return CircularDependencyResult(
                    cycles=(),
                    has_cycles=False,
                    checked=False,
                    status="INVALID_CHILDREN_COLLECTION",
                )

            try:
                children = tuple(raw_children)
            except TypeError:
                return CircularDependencyResult(
                    cycles=(),
                    has_cycles=False,
                    checked=False,
                    status="INVALID_CHILDREN_COLLECTION",
                )

            normalized_node = raw_node.strip()
            normalized_children: list[str] = []

            for child in children:
                if not isinstance(child, str) or not child.strip():
                    return CircularDependencyResult(
                        cycles=(),
                        has_cycles=False,
                        checked=False,
                        status="INVALID_CHILD_NAME",
                    )

                normalized_children.append(child.strip())

            normalized[normalized_node] = tuple(normalized_children)

    except (TypeError, ValueError):
        return CircularDependencyResult(
            cycles=(),
            has_cycles=False,
            checked=False,
            status="INVALID_GRAPH",
        )

    # Include dependency targets that are not explicit graph keys.
    all_nodes = set(normalized)
    for children in normalized.values():
        all_nodes.update(children)

    for node in all_nodes:
        normalized.setdefault(node, ())

    cycles: set[tuple[str, ...]] = set()
    state: dict[str, int] = {}
    stack: list[str] = []
    stack_index: dict[str, int] = {}

    def canonical_cycle(cycle: Sequence[str]) -> tuple[str, ...]:
        values = tuple(cycle)

        rotations = [
            values[index:] + values[:index]
            for index in range(len(values))
        ]

        return min(rotations)

    def dfs(node: str) -> None:
        state[node] = 1
        stack_index[node] = len(stack)
        stack.append(node)

        for child in sorted(normalized[node]):
            child_state = state.get(child, 0)

            if child_state == 0:
                dfs(child)

            elif child_state == 1:
                start = stack_index[child]
                cycle = stack[start:]
                cycles.add(canonical_cycle(cycle))

        stack.pop()
        stack_index.pop(node, None)
        state[node] = 2

    for node in sorted(all_nodes):
        if state.get(node, 0) == 0:
            dfs(node)

    ordered_cycles = tuple(
        sorted(
            cycles,
            key=lambda cycle: (len(cycle), cycle),
        )
    )

    return CircularDependencyResult(
        cycles=ordered_cycles,
        has_cycles=bool(ordered_cycles),
        checked=True,
        status=(
            "CIRCULAR_DEPENDENCIES_FOUND"
            if ordered_cycles
            else "NO_CIRCULAR_DEPENDENCIES"
        ),
    )
