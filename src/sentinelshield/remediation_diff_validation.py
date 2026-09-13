from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class RemediationDiffValidationInput:
    expected_files: Tuple[str, ...]
    changed_files: Tuple[str, ...]
    forbidden_files: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RemediationDiffValidationResult:
    expected_files: Tuple[str, ...]
    changed_files: Tuple[str, ...]
    unexpected_files: Tuple[str, ...]
    forbidden_changes: Tuple[str, ...]
    status: str


def _files(value, name):
    if not isinstance(value, tuple):
        raise TypeError(f"{name}_MUST_BE_TUPLE")
    out = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{name}_MUST_CONTAIN_STRINGS")
        if not item or "\x00" in item:
            raise ValueError(f"{name}_CONTAINS_INVALID_PATH")
        out.append(item)
    return tuple(sorted(set(out)))


def validate_remediation_diff(
    request: RemediationDiffValidationInput,
) -> RemediationDiffValidationResult:
    if not isinstance(request, RemediationDiffValidationInput):
        raise TypeError("INPUT_MUST_BE_REMEDIATION_DIFF_VALIDATION_INPUT")

    expected = _files(request.expected_files, "EXPECTED_FILES")
    changed = _files(request.changed_files, "CHANGED_FILES")
    forbidden = _files(request.forbidden_files, "FORBIDDEN_FILES")

    unexpected = tuple(sorted(set(changed) - set(expected)))
    forbidden_changes = tuple(sorted(set(changed) & set(forbidden)))

    status = "PASS" if not unexpected and not forbidden_changes else "FAIL"

    return RemediationDiffValidationResult(
        expected_files=expected,
        changed_files=changed,
        unexpected_files=unexpected,
        forbidden_changes=forbidden_changes,
        status=status,
    )


def remediation_diff_validation(
    request: RemediationDiffValidationInput,
) -> RemediationDiffValidationResult:
    return validate_remediation_diff(request)


__all__ = [
    "RemediationDiffValidationInput",
    "RemediationDiffValidationResult",
    "validate_remediation_diff",
    "remediation_diff_validation",
]
