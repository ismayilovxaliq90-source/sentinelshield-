from dataclasses import dataclass
from typing import Mapping

__test__ = False

@dataclass(frozen=True)
class DependencyTreeSecurityComparisonInput:
    before: Mapping[str, tuple[str, ...]]
    after: Mapping[str, tuple[str, ...]]

@dataclass(frozen=True)
class DependencyTreeSecurityComparisonResult:
    added_edges: tuple[str, ...]
    removed_edges: tuple[str, ...]
    changed_nodes: tuple[str, ...]
    status: str

def _validate(x):
    if not isinstance(x, DependencyTreeSecurityComparisonInput):
        raise TypeError("INPUT_MUST_BE_DEPENDENCY_TREE_SECURITY_COMPARISON_INPUT")
    for name, tree in (("before", x.before), ("after", x.after)):
        if not isinstance(tree, Mapping):
            raise TypeError(f"{name.upper()}_MUST_BE_MAPPING")
        for node, deps in tree.items():
            if not isinstance(node, str) or not node.strip():
                raise TypeError("NODE_MUST_BE_NONEMPTY_STRING")
            if not isinstance(deps, tuple):
                raise TypeError("DEPENDENCIES_MUST_BE_TUPLE")
            for dep in deps:
                if not isinstance(dep, str) or not dep.strip():
                    raise TypeError("DEPENDENCY_MUST_BE_NONEMPTY_STRING")
    return x

def compare_dependency_tree_security(request):
    x = _validate(request)

    def edges(tree):
        return {
            f"{node}->{dep}"
            for node, deps in tree.items()
            for dep in deps
        }

    before = edges(x.before)
    after = edges(x.after)
    added = tuple(sorted(after - before))
    removed = tuple(sorted(before - after))

    nodes = set(x.before) | set(x.after)
    changed = tuple(sorted(
        n for n in nodes
        if tuple(x.before.get(n, ())) != tuple(x.after.get(n, ()))
    ))

    status = "FAIL" if added else "PASS"
    return DependencyTreeSecurityComparisonResult(
        added, removed, changed, status
    )

def dependency_tree_security_comparison(request):
    return compare_dependency_tree_security(request)

dependency_tree_security_comparison.__test__ = False
