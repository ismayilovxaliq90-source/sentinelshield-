from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class DependencyGraphNode:
    name: str
    version: Optional[str]
    dependency_type: str
    source: Optional[str] = None


@dataclass(frozen=True)
class DependencyGraphEdge:
    parent: str
    child: str


@dataclass(frozen=True)
class DependencyGraph:
    nodes: tuple[DependencyGraphNode, ...]
    edges: tuple[DependencyGraphEdge, ...]


@dataclass(frozen=True)
class DependencyGraphConstructionResult:
    graph: DependencyGraph
    constructed: bool
    status: str


def _dependency_name(value: object) -> Optional[str]:
    name = getattr(value, "name", None)

    if not isinstance(name, str):
        return None

    name = name.strip()

    return name or None


def _dependency_version(value: object) -> Optional[str]:
    version = getattr(value, "version", None)

    if version is None:
        return None

    if not isinstance(version, str):
        return None

    return version


def _dependency_type(value: object) -> Optional[str]:
    dependency_type = getattr(value, "dependency_type", None)

    if not isinstance(dependency_type, str):
        return None

    dependency_type = dependency_type.strip().lower()

    return dependency_type or None


def _dependency_source(value: object) -> Optional[str]:
    source = getattr(value, "source", None)

    if source is None:
        return None

    if not isinstance(source, str):
        return None

    return source


def construct_dependency_graph(
    dependencies: Iterable[object],
) -> DependencyGraphConstructionResult:
    """
    Construct a deterministic dependency graph from an existing
    dependency inventory.

    This operation is strictly read-only.

    It does not:
      - install packages
      - modify manifests
      - modify lockfiles
      - execute package-manager commands
      - execute project code
      - modify the filesystem
    """

    if dependencies is None:
        return DependencyGraphConstructionResult(
            graph=DependencyGraph(nodes=(), edges=()),
            constructed=False,
            status="DEPENDENCIES_IS_NONE",
        )

    if isinstance(dependencies, (str, bytes)):
        return DependencyGraphConstructionResult(
            graph=DependencyGraph(nodes=(), edges=()),
            constructed=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    try:
        items = tuple(dependencies)
    except TypeError:
        return DependencyGraphConstructionResult(
            graph=DependencyGraph(nodes=(), edges=()),
            constructed=False,
            status="UNSUPPORTED_DEPENDENCY_COLLECTION",
        )

    nodes_by_name: dict[str, DependencyGraphNode] = {}
    edges: set[tuple[str, str]] = set()

    for item in items:
        name = _dependency_name(item)

        if name is None:
            return DependencyGraphConstructionResult(
                graph=DependencyGraph(nodes=(), edges=()),
                constructed=False,
                status="INVALID_DEPENDENCY_NAME",
            )

        version = _dependency_version(item)

        if getattr(item, "version", None) is not None and version is None:
            return DependencyGraphConstructionResult(
                graph=DependencyGraph(nodes=(), edges=()),
                constructed=False,
                status="INVALID_DEPENDENCY_VERSION",
            )

        dependency_type = _dependency_type(item)

        if dependency_type is None:
            return DependencyGraphConstructionResult(
                graph=DependencyGraph(nodes=(), edges=()),
                constructed=False,
                status="INVALID_DEPENDENCY_TYPE",
            )

        source = _dependency_source(item)

        if getattr(item, "source", None) is not None and source is None:
            return DependencyGraphConstructionResult(
                graph=DependencyGraph(nodes=(), edges=()),
                constructed=False,
                status="INVALID_DEPENDENCY_SOURCE",
            )

        node = DependencyGraphNode(
            name=name,
            version=version,
            dependency_type=dependency_type,
            source=source,
        )

        existing = nodes_by_name.get(name)

        if existing is None:
            nodes_by_name[name] = node
        elif existing != node:
            return DependencyGraphConstructionResult(
                graph=DependencyGraph(nodes=(), edges=()),
                constructed=False,
                status="DUPLICATE_DEPENDENCY_CONFLICT",
            )

    nodes = tuple(
        sorted(
            nodes_by_name.values(),
            key=lambda node: (
                node.name.casefold(),
                0 if node.name[:1].islower() else 1,
                node.name,
                node.version or "",
                node.dependency_type,
                node.source or "",
            ),
        )
    )

    graph = DependencyGraph(
        nodes=nodes,
        edges=tuple(
            DependencyGraphEdge(parent=parent, child=child)
            for parent, child in sorted(
                edges,
                key=lambda edge: (
                    edge[0].casefold(),
                    edge[0],
                    edge[1].casefold(),
                    edge[1],
                ),
            )
        ),
    )

    return DependencyGraphConstructionResult(
        graph=graph,
        constructed=True,
        status="GRAPH_CONSTRUCTED",
    )


def build_dependency_graph(
    dependencies: Iterable[object],
) -> DependencyGraphConstructionResult:
    return construct_dependency_graph(dependencies)
