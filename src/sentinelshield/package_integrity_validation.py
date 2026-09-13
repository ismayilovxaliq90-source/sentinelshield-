from dataclasses import dataclass
from typing import Mapping

__test__ = False

@dataclass(frozen=True)
class PackageIntegrityValidationInput:
    expected: Mapping[str, str]
    actual: Mapping[str, str]

@dataclass(frozen=True)
class PackageIntegrityValidationResult:
    valid: tuple[str, ...]
    invalid: tuple[str, ...]
    missing: tuple[str, ...]
    unexpected: tuple[str, ...]
    status: str

def _validate(x):
    if not isinstance(x, PackageIntegrityValidationInput):
        raise TypeError("INPUT_MUST_BE_PACKAGE_INTEGRITY_VALIDATION_INPUT")
    for name, data in (("expected", x.expected), ("actual", x.actual)):
        if not isinstance(data, Mapping):
            raise TypeError(f"{name.upper()}_MUST_BE_MAPPING")
        for k, v in data.items():
            if not isinstance(k, str) or not k.strip():
                raise TypeError("PACKAGE_NAME_MUST_BE_NONEMPTY_STRING")
            if not isinstance(v, str) or not v.strip():
                raise TypeError("INTEGRITY_VALUE_MUST_BE_NONEMPTY_STRING")
    return x

def validate_package_integrity(request):
    x = _validate(request)
    expected = {k: v for k, v in x.expected.items()}
    actual = {k: v for k, v in x.actual.items()}
    common = set(expected) & set(actual)
    valid = tuple(sorted(k for k in common if expected[k] == actual[k]))
    invalid = tuple(sorted(k for k in common if expected[k] != actual[k]))
    missing = tuple(sorted(set(expected) - set(actual)))
    unexpected = tuple(sorted(set(actual) - set(expected)))
    status = "PASS" if not invalid and not missing and not unexpected else "FAIL"
    return PackageIntegrityValidationResult(
        valid, invalid, missing, unexpected, status
    )

def package_integrity_validation(request):
    return validate_package_integrity(request)

package_integrity_validation.__test__ = False
