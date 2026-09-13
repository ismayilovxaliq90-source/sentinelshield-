from dataclasses import dataclass
from typing import Mapping

__test__ = False

@dataclass(frozen=True)
class ReachabilityChangeComparisonInput:
    before: Mapping[str, bool]
    after: Mapping[str, bool]

@dataclass(frozen=True)
class ReachabilityChangeComparisonResult:
    became_reachable: tuple[str, ...]
    became_unreachable: tuple[str, ...]
    unchanged: tuple[str, ...]
    status: str

def _validate(x):
    if not isinstance(x, ReachabilityChangeComparisonInput):
        raise TypeError("INPUT_MUST_BE_REACHABILITY_CHANGE_COMPARISON_INPUT")
    for name, data in (("before", x.before), ("after", x.after)):
        if not isinstance(data, Mapping):
            raise TypeError(f"{name.upper()}_MUST_BE_MAPPING")
        for k, v in data.items():
            if not isinstance(k, str) or not k.strip():
                raise TypeError("VULNERABILITY_ID_MUST_BE_NONEMPTY_STRING")
            if not isinstance(v, bool):
                raise TypeError("REACHABILITY_MUST_BE_BOOL")
    return x

def compare_reachability_changes(request):
    x = _validate(request)
    before = dict(x.before)
    after = dict(x.after)
    common = set(before) & set(after)
    became_reachable = tuple(sorted(
        k for k in common if not before[k] and after[k]
    ))
    became_unreachable = tuple(sorted(
        k for k in common if before[k] and not after[k]
    ))
    unchanged = tuple(sorted(
        k for k in common if before[k] == after[k]
    ))
    status = "FAIL" if became_reachable else "PASS"
    return ReachabilityChangeComparisonResult(
        became_reachable, became_unreachable, unchanged, status
    )

def reachability_change_comparison(request):
    return compare_reachability_changes(request)

reachability_change_comparison.__test__ = False
