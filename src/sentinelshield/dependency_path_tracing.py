from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class DependencyPath:
    source: str
    target: str
    path: tuple[str, ...]


@dataclass(frozen=True)
class DependencyPathTracingResult:
    paths: tuple[DependencyPath, ...]
    traced: bool
    status: str


def trace_dependency_paths(
    edges: Iterable[object],
    source: object,
    target: object,
) -> DependencyPathTracingResult:
    if edges is None:
        return DependencyPathTracingResult((), False, "EDGES_IS_NONE")

    if not isinstance(source, str) or not source.strip():
        return DependencyPathTracingResult((), False, "INVALID_SOURCE")

    if not isinstance(target, str) or not target.strip():
        return DependencyPathTracingResult((), False, "INVALID_TARGET")

    source = source.strip()
    target = target.strip()

    if isinstance(edges, (str, bytes)):
        return DependencyPathTracingResult(
            (), False, "UNSUPPORTED_EDGE_COLLECTION"
        )

    try:
        items = tuple(edges)
    except TypeError:
        return DependencyPathTracingResult(
            (), False, "UNSUPPORTED_EDGE_COLLECTION"
        )

    graph: dict[str, set[str]] = {}

    for edge in items:
        if isinstance(edge, dict):
            parent = edge.get("parent")
            child = edge.get("child")
        elif isinstance(edge, (tuple, list)) and len(edge) == 2:
            parent, child = edge
        else:
            parent = getattr(edge, "parent", None)
            child = getattr(edge, "child", None)

        if not isinstance(parent, str) or not parent.strip():
            return DependencyPathTracingResult((), False, "INVALID_PARENT")

        if not isinstance(child, str) or not child.strip():
            return DependencyPathTracingResult((), False, "INVALID_CHILD")

        parent = parent.strip()
        child = child.strip()

        graph.setdefault(parent, set()).add(child)

    if source == target:
        return DependencyPathTracingResult(
            (
                DependencyPath(
                    source=source,
                    target=target,
                    path=(source,),
                ),
            ),
            True,
            "PATH_FOUND",
        )

    found: list[DependencyPath] = []
    stack: list[tuple[str, tuple[str, ...]]] = [
        (source, (source,))
    ]

    while stack:
        current, path = stack.pop()

        for child in sorted(
            graph.get(current, ()),
            reverse=True,
        ):
            if child in path:
                continue

            next_path = path + (child,)

            if child == target:
                found.append(
                    DependencyPath(
                        source=source,
                        target=target,
                        path=next_path,
                    )
                )
                continue

            stack.append((child, next_path))

    found.sort(key=lambda item: item.path)

    return DependencyPathTracingResult(
        paths=tuple(found),
        traced=True,
        status="PATH_FOUND" if found else "PATH_NOT_FOUND",
    )
