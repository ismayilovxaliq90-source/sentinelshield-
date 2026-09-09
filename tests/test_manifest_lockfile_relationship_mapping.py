from pathlib import Path

from sentinelshield.manifest_lockfile_relationship_mapping import (
    ManifestLockfileRelationship,
    ManifestLockfileRelationshipMappingResult,
    map_manifest_lockfile_relationships,
)


def test_package_json_to_package_lock(tmp_path: Path):
    manifest = tmp_path / "package.json"
    lockfile = tmp_path / "package-lock.json"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.found is True
    assert result.relationships == (
        ManifestLockfileRelationship(
            manifest=manifest.resolve(),
            lockfiles=(lockfile.resolve(),),
        ),
    )
    assert result.unmatched_manifests == ()
    assert result.unmatched_lockfiles == ()


def test_package_json_supports_yarn_lock(tmp_path: Path):
    manifest = tmp_path / "package.json"
    lockfile = tmp_path / "yarn.lock"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0].manifest == manifest.resolve()
    assert result.relationships[0].lockfiles == (lockfile.resolve(),)


def test_package_json_supports_pnpm_lock(tmp_path: Path):
    manifest = tmp_path / "package.json"
    lockfile = tmp_path / "pnpm-lock.yaml"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0].lockfiles == (lockfile.resolve(),)


def test_cargo_mapping(tmp_path: Path):
    manifest = tmp_path / "Cargo.toml"
    lockfile = tmp_path / "Cargo.lock"

    manifest.write_text("", encoding="utf-8")
    lockfile.write_text("", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0] == ManifestLockfileRelationship(
        manifest=manifest.resolve(),
        lockfiles=(lockfile.resolve(),),
    )


def test_composer_mapping(tmp_path: Path):
    manifest = tmp_path / "composer.json"
    lockfile = tmp_path / "composer.lock"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0].manifest == manifest.resolve()
    assert result.relationships[0].lockfiles == (lockfile.resolve(),)


def test_python_mapping(tmp_path: Path):
    manifest = tmp_path / "Pipfile"
    lockfile = tmp_path / "Pipfile.lock"

    manifest.write_text("", encoding="utf-8")
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0].manifest == manifest.resolve()
    assert result.relationships[0].lockfiles == (lockfile.resolve(),)


def test_pyproject_poetry_mapping(tmp_path: Path):
    manifest = tmp_path / "pyproject.toml"
    lockfile = tmp_path / "poetry.lock"

    manifest.write_text("", encoding="utf-8")
    lockfile.write_text("", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0].manifest == manifest.resolve()
    assert result.relationships[0].lockfiles == (lockfile.resolve(),)


def test_unmatched_manifest(tmp_path: Path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.found is False
    assert result.relationships == ()
    assert result.unmatched_manifests == (manifest.resolve(),)


def test_unmatched_lockfile(tmp_path: Path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.found is False
    assert result.unmatched_lockfiles == (lockfile.resolve(),)


def test_nested_relationship(tmp_path: Path):
    project = tmp_path / "services" / "api"
    project.mkdir(parents=True)

    manifest = project / "package.json"
    lockfile = project / "package-lock.json"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0].manifest == manifest.resolve()
    assert result.relationships[0].lockfiles == (lockfile.resolve(),)


def test_different_directories_are_not_related(tmp_path: Path):
    manifest_dir = tmp_path / "frontend"
    lockfile_dir = tmp_path / "backend"

    manifest_dir.mkdir()
    lockfile_dir.mkdir()

    manifest = manifest_dir / "package.json"
    lockfile = lockfile_dir / "package-lock.json"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "NOT_FOUND"
    assert result.relationships == ()
    assert result.unmatched_manifests == (manifest.resolve(),)
    assert result.unmatched_lockfiles == (lockfile.resolve(),)


def test_case_insensitive_names(tmp_path: Path):
    manifest = tmp_path / "PACKAGE.JSON"
    lockfile = tmp_path / "PACKAGE-LOCK.JSON"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    assert result.status == "FOUND"
    assert result.relationships[0].manifest == manifest.resolve()
    assert result.relationships[0].lockfiles == (lockfile.resolve(),)


def test_none_path():
    result = map_manifest_lockfile_relationships(None)

    assert result.status == "PATH_IS_NONE"
    assert result.found is False
    assert result.relationships == ()


def test_empty_path():
    result = map_manifest_lockfile_relationships("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.found is False


def test_unsupported_path_type():
    result = map_manifest_lockfile_relationships(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.found is False


def test_result_type(tmp_path: Path):
    result = map_manifest_lockfile_relationships(tmp_path)

    assert isinstance(result, ManifestLockfileRelationshipMappingResult)


def test_relationship_is_immutable(tmp_path: Path):
    manifest = tmp_path / "package.json"
    lockfile = tmp_path / "package-lock.json"

    manifest.write_text("{}", encoding="utf-8")
    lockfile.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    try:
        result.found = False
    except Exception:
        return

    raise AssertionError("Result must be immutable")


def test_deterministic_order(tmp_path: Path):
    for name in (
        "z/package.json",
        "a/package.json",
        "z/package-lock.json",
        "a/package-lock.json",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")

    result = map_manifest_lockfile_relationships(tmp_path)

    manifests = tuple(
        relationship.manifest
        for relationship in result.relationships
    )

    assert manifests == tuple(sorted(manifests, key=str))
