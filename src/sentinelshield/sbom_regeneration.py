from dataclasses import dataclass
from typing import Mapping

__test__ = False

@dataclass(frozen=True)
class SBOMRegenerationInput:
    packages: Mapping[str, str]

@dataclass(frozen=True)
class SBOMRegenerationResult:
    packages: tuple[tuple[str, str], ...]
    package_count: int
    regenerated: bool
    status: str

def _validate(x):
    if not isinstance(x, SBOMRegenerationInput):
        raise TypeError("INPUT_MUST_BE_SBOM_REGENERATION_INPUT")
    if not isinstance(x.packages, Mapping):
        raise TypeError("PACKAGES_MUST_BE_MAPPING")
    for name, version in x.packages.items():
        if not isinstance(name, str) or not name.strip():
            raise TypeError("PACKAGE_NAME_MUST_BE_NONEMPTY_STRING")
        if not isinstance(version, str) or not version.strip():
            raise TypeError("PACKAGE_VERSION_MUST_BE_NONEMPTY_STRING")
    return x

def regenerate_sbom(request):
    x = _validate(request)
    packages = tuple(sorted(
        ((name, version) for name, version in x.packages.items()),
        key=lambda item: item[0],
    ))
    return SBOMRegenerationResult(
        packages=packages,
        package_count=len(packages),
        regenerated=True,
        status="PASS",
    )

def sbom_regeneration(request):
    return regenerate_sbom(request)

sbom_regeneration.__test__ = False
