from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import re
import tempfile


class ManifestModificationError(ValueError):
    """Raised when a manifest modification cannot be performed safely."""


@dataclass(frozen=True)
class ManifestModificationPolicy:
    allowed_manifest_names: tuple[str, ...] = (
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "package.json",
        "pom.xml",
        "build.gradle",
        "go.mod",
        "Cargo.toml",
        "composer.json",
    )
    reject_symlinks: bool = True
    require_single_target: bool = True
    create_backup: bool = True


@dataclass(frozen=True)
class ManifestModificationResult:
    modified: bool
    manifest: str
    dependency: str
    old_value: str | None
    new_value: str
    changes: int
    original_sha256: str
    final_sha256: str
    original_content: str
    final_content: str

    @property
    def safe(self) -> bool:
        return self.changes == 1 and self.modified

    def to_dict(self) -> dict[str, Any]:
        return {
            "modified": self.modified,
            "manifest": self.manifest,
            "dependency": self.dependency,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "changes": self.changes,
            "original_sha256": self.original_sha256,
            "final_sha256": self.final_sha256,
            "original_content": self.original_content,
            "final_content": self.final_content,
        }


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _validate_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ManifestModificationError(f"{field} must be string")

    if not value.strip():
        raise ManifestModificationError(f"{field} must not be empty")

    if "\x00" in value:
        raise ManifestModificationError(
            f"{field} contains NUL character"
        )

    return value


def _validate_dependency_name(name: str) -> None:
    if "/" in name or "\\" in name:
        raise ManifestModificationError(
            "dependency name must not contain path separators"
        )

    if ".." in name:
        raise ManifestModificationError(
            "dependency name must not contain traversal"
        )


def _validate_manifest_path(
    repository_root: Path,
    manifest_path: Path,
    policy: ManifestModificationPolicy,
) -> Path:
    root = repository_root.resolve(strict=True)
    candidate = manifest_path

    if not candidate.is_absolute():
        candidate = root / candidate

    if policy.reject_symlinks:
        current = candidate
        while current != root:
            if current.is_symlink():
                raise ManifestModificationError(
                    "MANIFEST_SYMLINK_NOT_ALLOWED"
                )
            if current.parent == current:
                break
            current = current.parent

    resolved = candidate.resolve(strict=True)

    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ManifestModificationError(
            "MANIFEST_OUTSIDE_REPOSITORY"
        ) from error

    if resolved.name not in policy.allowed_manifest_names:
        raise ManifestModificationError(
            f"MANIFEST_TYPE_NOT_ALLOWED: {resolved.name}"
        )

    if not resolved.is_file():
        raise ManifestModificationError(
            "MANIFEST_NOT_REGULAR_FILE"
        )

    return resolved


def _replace_requirements_dependency(
    content: str,
    dependency: str,
    new_value: str,
) -> tuple[str, str | None, int]:
    pattern = re.compile(
        rf"^(?P<prefix>\s*{re.escape(dependency)}"
        rf"(?P<constraint>\s*(?:==|~=|>=|<=|>|<|!=|===)\s*[^#\r\n]+)?"
        rf"(?P<suffix>\s*(?:#.*)?)?)$",
        re.MULTILINE,
    )

    matches = list(pattern.finditer(content))

    if len(matches) != 1:
        return content, None, len(matches)

    match = matches[0]
    old_line = match.group(0)

    suffix = match.group("suffix") or ""
    new_line = f"{dependency}{new_value}{suffix}"

    updated = (
        content[:match.start()]
        + new_line
        + content[match.end():]
    )

    old_value = match.group("constraint")
    if old_value is not None:
        old_value = old_value.strip()

    return updated, old_value, 1


def _replace_json_dependency(
    content: str,
    dependency: str,
    new_value: str,
) -> tuple[str, str | None, int]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as error:
        raise ManifestModificationError(
            "INVALID_JSON_MANIFEST"
        ) from error

    sections = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    )

    locations: list[str] = []

    for section in sections:
        values = document.get(section)
        if isinstance(values, dict) and dependency in values:
            locations.append(section)

    if len(locations) != 1:
        return content, None, len(locations)

    section = locations[0]
    old_value = document[section][dependency]
    document[section][dependency] = new_value

    updated = json.dumps(
        document,
        indent=2,
        ensure_ascii=False,
    ) + "\n"

    return updated, str(old_value), 1


def _modify_content(
    manifest_path: Path,
    content: str,
    dependency: str,
    new_value: str,
) -> tuple[str, str | None, int]:
    if manifest_path.name == "package.json":
        return _replace_json_dependency(
            content,
            dependency,
            new_value,
        )

    if manifest_path.name == "requirements.txt":
        return _replace_requirements_dependency(
            content,
            dependency,
            new_value,
        )

    raise ManifestModificationError(
        f"MANIFEST_FORMAT_NOT_IMPLEMENTED: {manifest_path.name}"
    )


def modify_manifest(
    *,
    repository_root: str | os.PathLike[str],
    manifest: str | os.PathLike[str],
    dependency: str,
    new_value: str,
    policy: ManifestModificationPolicy | None = None,
) -> ManifestModificationResult:
    policy = policy or ManifestModificationPolicy()

    if not isinstance(policy, ManifestModificationPolicy):
        raise ManifestModificationError("invalid policy")

    root = Path(repository_root)
    manifest_input = Path(manifest)

    _validate_text(str(root), "repository_root")
    _validate_text(str(manifest_input), "manifest")
    dependency = _validate_text(dependency, "dependency")
    new_value = _validate_text(new_value, "new_value")

    _validate_dependency_name(dependency)

    if root.is_symlink():
        raise ManifestModificationError(
            "REPOSITORY_ROOT_SYMLINK_NOT_ALLOWED"
        )

    if not root.is_dir():
        raise ManifestModificationError(
            "REPOSITORY_ROOT_NOT_DIRECTORY"
        )

    resolved_manifest = _validate_manifest_path(
        root,
        manifest_input,
        policy,
    )

    original = resolved_manifest.read_text(
        encoding="utf-8"
    )

    updated, old_value, changes = _modify_content(
        resolved_manifest,
        original,
        dependency,
        new_value,
    )

    if changes != 1:
        raise ManifestModificationError(
            f"TARGET_CHANGE_COUNT_INVALID: {changes}"
        )

    if updated == original:
        raise ManifestModificationError(
            "NO_EFFECTIVE_MANIFEST_CHANGE"
        )

    if policy.create_backup:
        backup = Path(
            tempfile.mkstemp(
                prefix=f"{resolved_manifest.name}.",
                suffix=".backup",
                dir=str(resolved_manifest.parent),
            )[1]
        )
        try:
            backup.write_text(
                original,
                encoding="utf-8",
            )
            os.chmod(backup, 0o600)
        finally:
            if backup.exists():
                backup.unlink()

    resolved_manifest.write_text(
        updated,
        encoding="utf-8",
    )

    return ManifestModificationResult(
        modified=True,
        manifest=str(resolved_manifest),
        dependency=dependency,
        old_value=old_value,
        new_value=new_value,
        changes=changes,
        original_sha256=_sha256(original),
        final_sha256=_sha256(updated),
        original_content=original,
        final_content=updated,
    )


def validate_manifest_modification(
    result: ManifestModificationResult,
) -> bool:
    if not isinstance(result, ManifestModificationResult):
        raise ManifestModificationError("invalid result")

    if not result.modified:
        return False

    if result.changes != 1:
        return False

    if result.original_sha256 == result.final_sha256:
        return False

    return True
