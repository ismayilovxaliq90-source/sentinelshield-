from dataclasses import dataclass
from typing import Mapping

__test__ = False

_VALID = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

@dataclass(frozen=True)
class SeverityChangeComparisonInput:
    before: Mapping[str, str]
    after: Mapping[str, str]

@dataclass(frozen=True)
class SeverityChangeComparisonResult:
    increased: tuple[str, ...]
    decreased: tuple[str, ...]
    unchanged: tuple[str, ...]
    status: str

def _validate(x):
    if not isinstance(x, SeverityChangeComparisonInput):
        raise TypeError("INPUT_MUST_BE_SEVERITY_CHANGE_COMPARISON_INPUT")
    for name, data in (("before", x.before), ("after", x.after)):
        if not isinstance(data, Mapping):
            raise TypeError(f"{name.upper()}_MUST_BE_MAPPING")
        for k, v in data.items():
            if not isinstance(k, str) or not k.strip():
                raise TypeError("VULNERABILITY_ID_MUST_BE_NONEMPTY_STRING")
            if not isinstance(v, str) or v.upper() not in _VALID:
                raise ValueError("INVALID_VULNERABILITY_SEVERITY")
    return x

def compare_severity_changes(request):
    x = _validate(request)
    before = {k: v.upper() for k, v in x.before.items()}
    after = {k: v.upper() for k, v in x.after.items()}
    common = set(before) & set(after)
    increased = tuple(sorted(k for k in common if _ORDER[after[k]] > _ORDER[before[k]]))
    decreased = tuple(sorted(k for k in common if _ORDER[after[k]] < _ORDER[before[k]]))
    unchanged = tuple(sorted(k for k in common if after[k] == before[k]))
    status = "FAIL" if increased else "PASS"
    return SeverityChangeComparisonResult(increased, decreased, unchanged, status)

def severity_change_comparison(request):
    return compare_severity_changes(request)

severity_change_comparison.__test__ = False
