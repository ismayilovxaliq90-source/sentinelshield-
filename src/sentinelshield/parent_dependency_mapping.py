from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParentDependencyMappingResult:
    parents: dict[str, tuple[str, ...]]
    mapped: bool
    status: str


def _name(value: object) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None

    name = getattr(value, "name", None)

    if isinstance(name, str):
        name = name.strip()
        return name or None

    return None


def _children(value: object):
    for attr in (
        "dependencies",
        "children",
        "transitive_dependencies",
    ):
        if hasattr(value, attr):
            children = getattr(value, attr)

            if children is None:
                return ()

            if isinstance(children, (str, bytes)):
                return None

            try:
                return tuple(children)
            except TypeError:
                return None

    return ()


def map_parent_dependencies(
    dependency_graph: Any,
) -> ParentDependencyMappingResult:

    if dependency_graph is None:
        return ParentDependencyMappingResult(
            parents={},
            mapped=False,
            status="GRAPH_IS_NONE",
        )

    if isinstance(dependency_graph, (str, bytes)):
        return ParentDependencyMappingResult(
            parents={},
            mapped=False,
            status="UNSUPPORTED_GRAPH_TYPE",
        )

    try:
        nodes = tuple(dependency_graph)
    except TypeError:
        return ParentDependencyMappingResult(
            parents={},
            mapped=False,
            status="UNSUPPORTED_GRAPH_TYPE",
        )

    parents: dict[str, set[str]] = {}

    for node in nodes:
        parent = _name(node)

        if parent is None:
            return ParentDependencyMappingResult(
                parents={},
                mapped=False,
                status="INVALID_PARENT_NODE",
            )

        children = _children(node)

        if children is None:
            return ParentDependencyMappingResult(
                parents={},
                mapped=False,
                status="INVALID_CHILD_COLLECTION",
            )

        parents.setdefault(parent, set())

        for child in children:
            child_name = _name(child)

            if child_name is None:
                return ParentDependencyMappingResult(
                    parents={},
                    mapped=False,
                    status="INVALID_CHILD_NODE",
                )

            if child_name == parent:
                continue

            parents[parent].add(child_name)

    normalized = {
        parent: tuple(
            sorted(
                children,
                key=lambda value: (
                    value.casefold(),
                    0 if value[:1].islower() else 1,
                    value,
                ),
            )
        )
        for parent, children in sorted(
            parents.items(),
            key=lambda item: (
                item[0].casefold(),
                0 if item[0][:1].islower() else 1,
                item[0],
            ),
        )
    }

    return ParentDependencyMappingResult(
        parents=normalized,
        mapped=True,
        status="MAPPED",
    )


def build_parent_dependency_mapping(
    dependency_graph: Any,
) -> ParentDependencyMappingResult:
    return map_parent_dependencies(dependency_graph)
