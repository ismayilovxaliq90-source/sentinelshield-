from dataclasses import dataclass
from typing import Mapping

__test__ = False

@dataclass(frozen=True)
class SupplyChainValidationInput:
    packages: Mapping[str, str]
    sources: Mapping[str, str]

@dataclass(frozen=True)
class SupplyChainValidationResult:
    validated: tuple[str, ...]
    invalid: tuple[str, ...]
    status: str

def _validate(x):
    if not isinstance(x, SupplyChainValidationInput):
        raise TypeError("INPUT_MUST_BE_SUPPLY_CHAIN_VALIDATION_INPUT")
    for name, data in (("packages", x.packages), ("sources", x.sources)):
        if not isinstance(data, Mapping):
            raise TypeError(f"{name.upper()}_MUST_BE_MAPPING")
        for k, v in data.items():
            if not isinstance(k, str) or not k.strip():
                raise TypeError("PACKAGE_NAME_MUST_BE_NONEMPTY_STRING")
            if not isinstance(v, str) or not v.strip():
                raise TypeError("SOURCE_MUST_BE_NONEMPTY_STRING")
    return x

def validate_supply_chain(request):
    x = _validate(request)
    validated = []
    invalid = []
    for package in sorted(set(x.packages) | set(x.sources)):
        source = x.sources.get(package)
        version = x.packages.get(package)
        if version and source:
            validated.append(package)
        else:
            invalid.append(package)
    validated = tuple(validated)
    invalid = tuple(invalid)
    return SupplyChainValidationResult(
        validated, invalid, "PASS" if not invalid else "FAIL"
    )

def supply_chain_validation(request):
    return validate_supply_chain(request)

supply_chain_validation.__test__ = False
