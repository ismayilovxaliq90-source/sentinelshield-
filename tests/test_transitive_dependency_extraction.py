from pathlib import Path

from sentinelshield.transitive_dependency_extraction import (
    TransitiveDependency,
    TransitiveDependencyExtractionResult,
    extract_transitive_dependencies,
)


def test_package_lock_extracts_transitive_dependency(tmp_path: Path):
    path = tmp_path / "package-lock.json"

    path.write_text(
        """
        {
          "name": "app",
          "packages": {
            "": {
              "dependencies": {
                "express": "^5.0.0"
              }
            },
            "node_modules/express": {
              "version": "5.0.0"
            },
            "node_modules/express/node_modules/body-parser": {
              "version": "2.2.0"
            }
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_transitive_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert TransitiveDependency(
        name="body-parser",
        version="2.2.0",
        parent="express",
        source="package-lock.json",
    ) in result.dependencies


def test_package_lock_excludes_root_package(tmp_path: Path):
    path = tmp_path / "package-lock.json"

    path.write_text(
        """
        {
          "packages": {
            "": {
              "name": "application",
              "version": "1.0.0"
            }
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_transitive_dependencies(path)

    assert result.dependencies == ()
    assert result.extracted is True


def test_package_lock_extracts_nested_parent(tmp_path: Path):
    path = tmp_path / "package-lock.json"

    path.write_text(
        """
        {
          "packages": {
            "": {},
            "node_modules/a": {
              "version": "1.0.0"
            },
            "node_modules/a/node_modules/b": {
              "version": "2.0.0"
            },
            "node_modules/a/node_modules/b/node_modules/c": {
              "version": "3.0.0"
            }
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_transitive_dependencies(path)

    assert TransitiveDependency(
        name="b",
        version="2.0.0",
        parent="a",
        source="package-lock.json",
    ) in result.dependencies

    assert TransitiveDependency(
        name="c",
        version="3.0.0",
        parent="b",
        source="package-lock.json",
    ) in result.dependencies


def test_yarn_lock_extracts_transitive_dependency(tmp_path: Path):
    path = tmp_path / "yarn.lock"

    path.write_text(
        """
        express@^5.0.0:
          version "5.0.0"
          dependencies:
            body-parser "^2.2.0"

        body-parser@^2.2.0:
          version "2.2.0"
        """,
        encoding="utf-8",
    )

    result = extract_transitive_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert TransitiveDependency(
        name="body-parser",
        version="^2.2.0",
        parent="express",
        source="yarn.lock",
    ) in result.dependencies


def test_yarn_scoped_package_parent_name(tmp_path: Path):
    path = tmp_path / "yarn.lock"

    path.write_text(
        """
        "@scope/package@^1.0.0":
          version "1.0.0"
          dependencies:
            lodash "^4.0.0"
        """,
        encoding="utf-8",
    )

    result = extract_transitive_dependencies(path)

    assert TransitiveDependency(
        name="lodash",
        version="^4.0.0",
        parent="@scope/package",
        source="yarn.lock",
    ) in result.dependencies


def test_pnpm_lock_extracts_transitive_dependency(tmp_path: Path):
    path = tmp_path / "pnpm-lock.yaml"

    path.write_text(
        """
        lockfileVersion: '9.0'

        snapshots:
          express@5.0.0:
            dependencies:
              body-parser: 2.2.0
        """,
        encoding="utf-8",
    )

    result = extract_transitive_dependencies(path)

    assert result.status == "EXTRACTED"
    assert result.extracted is True

    assert TransitiveDependency(
        name="body-parser",
        version="2.2.0",
        parent="express",
        source="pnpm-lock.yaml",
    ) in result.dependencies


def test_empty_supported_lockfile_is_successful(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text('{"packages": {}}', encoding="utf-8")

    result = extract_transitive_dependencies(path)

    assert result == TransitiveDependencyExtractionResult(
        lockfile_path=path.resolve(),
        dependencies=(),
        extracted=True,
        status="EXTRACTED",
    )


def test_invalid_package_lock_json(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text("{invalid", encoding="utf-8")

    result = extract_transitive_dependencies(path)

    assert result.dependencies == ()
    assert result.extracted is False
    assert result.status == "PARSE_ERROR"


def test_missing_packages_section(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text("{}", encoding="utf-8")

    result = extract_transitive_dependencies(path)

    assert result.dependencies == ()
    assert result.extracted is False
    assert result.status == "MISSING_PACKAGES_SECTION"


def test_unsupported_lockfile(tmp_path: Path):
    path = tmp_path / "unknown.lock"
    path.write_text("", encoding="utf-8")

    result = extract_transitive_dependencies(path)

    assert result == TransitiveDependencyExtractionResult(
        lockfile_path=path.resolve(),
        dependencies=(),
        extracted=False,
        status="UNSUPPORTED_LOCKFILE",
    )


def test_none_path():
    result = extract_transitive_dependencies(None)

    assert result == TransitiveDependencyExtractionResult(
        lockfile_path=None,
        dependencies=(),
        extracted=False,
        status="PATH_IS_NONE",
    )


def test_empty_path():
    result = extract_transitive_dependencies("   ")

    assert result.status == "PATH_IS_EMPTY"
    assert result.extracted is False


def test_null_character():
    result = extract_transitive_dependencies("/tmp/project\x00evil")

    assert result.status == "NULL_CHARACTER_NOT_ALLOWED"
    assert result.extracted is False


def test_unsupported_path_type():
    result = extract_transitive_dependencies(123)

    assert result.status == "UNSUPPORTED_PATH_TYPE"
    assert result.extracted is False


def test_missing_path(tmp_path: Path):
    path = tmp_path / "missing.lock"

    result = extract_transitive_dependencies(path)

    assert result.status == "PATH_NOT_FOUND"
    assert result.extracted is False


def test_directory_is_rejected(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.mkdir()

    result = extract_transitive_dependencies(path)

    assert result.status == "NOT_A_FILE"
    assert result.extracted is False


def test_result_is_immutable(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text('{"packages": {}}', encoding="utf-8")

    result = extract_transitive_dependencies(path)

    try:
        result.extracted = False
    except Exception:
        return

    raise AssertionError("Result must be immutable")


def test_dependency_is_immutable(tmp_path: Path):
    path = tmp_path / "package-lock.json"

    path.write_text(
        """
        {
          "packages": {
            "": {},
            "node_modules/a/node_modules/b": {
              "version": "2.0.0"
            }
          }
        }
        """,
        encoding="utf-8",
    )

    result = extract_transitive_dependencies(path)

    try:
        result.dependencies[0].name = "changed"
    except Exception:
        return

    raise AssertionError("Dependency must be immutable")


def test_extraction_does_not_modify_lockfile(tmp_path: Path):
    path = tmp_path / "package-lock.json"

    original = """
    {
      "packages": {
        "": {},
        "node_modules/a/node_modules/b": {
          "version": "2.0.0"
        }
      }
    }
    """

    path.write_text(original, encoding="utf-8")

    extract_transitive_dependencies(path)

    assert path.read_text(encoding="utf-8") == original


def test_deterministic_order(tmp_path: Path):
    path = tmp_path / "package-lock.json"

    path.write_text(
        """
        {
          "packages": {
            "": {},
            "node_modules/z/node_modules/b": {
              "version": "2.0.0"
            },
            "node_modules/a/node_modules/z": {
              "version": "1.0.0"
            }
          }
        }
        """,
        encoding="utf-8",
    )

    first = extract_transitive_dependencies(path)
    second = extract_transitive_dependencies(path)

    assert first == second
