from pathlib import Path

from sentinelshield.ecosystem_context import (
    EcosystemRecord,
    generate_ecosystem_context,
)


def test_single_ecosystem_context(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    record = EcosystemRecord(
        "python",
        True,
        "HIGH",
        (Path("pyproject.toml"),),
        ("PYPROJECT_TOML",),
        "PYTHON_ECOSYSTEM_DETECTED",
    )

    result = generate_ecosystem_context(root, [record])

    assert result.root == root.resolve()
    assert result.detected_ecosystems == ("python",)
    assert result.primary_ecosystem == "python"
    assert result.ecosystem_count == 1
    assert result.confidence == "HIGH"
    assert result.reason == "ECOSYSTEM_CONTEXT_CREATED"


def test_multi_ecosystem_context(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    records = [
        EcosystemRecord(
            "node",
            True,
            "HIGH",
            (Path("package.json"),),
            ("PACKAGE_JSON",),
            "NODEJS_ECOSYSTEM_DETECTED",
        ),
        EcosystemRecord(
            "python",
            True,
            "HIGH",
            (Path("pyproject.toml"),),
            ("PYPROJECT_TOML",),
            "PYTHON_ECOSYSTEM_DETECTED",
        ),
    ]

    result = generate_ecosystem_context(root, records)

    assert result.detected_ecosystems == ("node", "python")
    assert result.ecosystem_count == 2
    assert result.reason == "MULTI_ECOSYSTEM_CONTEXT_CREATED"


def test_primary_uses_confidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    records = [
        EcosystemRecord(
            "python",
            True,
            "MEDIUM",
            (Path("main.py"),),
            ("PYTHON_SOURCE",),
            "PYTHON_ECOSYSTEM_DETECTED",
        ),
        EcosystemRecord(
            "node",
            True,
            "HIGH",
            (Path("package.json"),),
            ("PACKAGE_JSON",),
            "NODEJS_ECOSYSTEM_DETECTED",
        ),
    ]

    result = generate_ecosystem_context(root, records)

    assert result.primary_ecosystem == "node"
    assert result.confidence == "HIGH"


def test_marker_count_breaks_confidence_tie(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    records = [
        EcosystemRecord(
            "python",
            True,
            "HIGH",
            (Path("pyproject.toml"), Path("requirements.txt")),
            ("PYPROJECT_TOML", "REQUIREMENTS_TXT"),
            "detected",
        ),
        EcosystemRecord(
            "node",
            True,
            "HIGH",
            (Path("package.json"),),
            ("PACKAGE_JSON",),
            "detected",
        ),
    ]

    result = generate_ecosystem_context(root, records)

    assert result.primary_ecosystem == "python"


def test_records_are_deterministically_sorted(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    records = [
        EcosystemRecord("rust", True, "HIGH", (), (), "detected"),
        EcosystemRecord("python", True, "HIGH", (), (), "detected"),
        EcosystemRecord("node", True, "HIGH", (), (), "detected"),
    ]

    result = generate_ecosystem_context(root, records)

    assert tuple(r.name for r in result.ecosystems) == (
        "node",
        "python",
        "rust",
    )


def test_duplicate_ecosystem_is_consolidated(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    records = [
        EcosystemRecord(
            "python",
            True,
            "MEDIUM",
            (Path("main.py"),),
            ("PYTHON_SOURCE",),
            "detected",
        ),
        EcosystemRecord(
            "python",
            True,
            "HIGH",
            (Path("pyproject.toml"),),
            ("PYPROJECT_TOML",),
            "detected",
        ),
    ]

    result = generate_ecosystem_context(root, records)

    assert result.ecosystem_count == 1
    assert result.primary_ecosystem == "python"
    assert result.ecosystems[0].confidence == "HIGH"


def test_no_ecosystem(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = generate_ecosystem_context(root, [])

    assert result.detected_ecosystems == ()
    assert result.primary_ecosystem is None
    assert result.ecosystem_count == 0
    assert result.confidence == "NONE"
    assert result.reason == "NO_ECOSYSTEM_DETECTED"


def test_dictionary_records_are_supported(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    records = [
        {
            "name": "node",
            "detected": True,
            "confidence": "HIGH",
            "markers": ["package.json"],
            "marker_types": ["PACKAGE_JSON"],
            "reason": "detected",
        }
    ]

    result = generate_ecosystem_context(root, records)

    assert result.primary_ecosystem == "node"
    assert result.ecosystems[0].markers == (
        Path("package.json"),
    )


def test_invalid_record_is_ignored(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = generate_ecosystem_context(
        root,
        [None, 123, {}, {"name": "python", "detected": True}],
    )

    assert result.detected_ecosystems == ("python",)


def test_none_root():
    result = generate_ecosystem_context(None, [])

    assert result.reason == "PATH_IS_NONE"


def test_empty_root():
    result = generate_ecosystem_context("   ", [])

    assert result.reason == "PATH_IS_EMPTY"


def test_unsupported_root():
    result = generate_ecosystem_context(123, [])

    assert result.reason == "UNSUPPORTED_PATH_TYPE"


def test_null_character():
    result = generate_ecosystem_context("/tmp/a\x00b", [])

    assert result.reason == "NULL_CHARACTER_NOT_ALLOWED"


def test_missing_root(tmp_path):
    result = generate_ecosystem_context(
        tmp_path / "missing",
        [],
    )

    assert result.reason == "PATH_DOES_NOT_EXIST"


def test_file_root(tmp_path):
    file = tmp_path / "file.txt"
    file.write_text("x")

    result = generate_ecosystem_context(file, [])

    assert result.reason == "PATH_IS_NOT_DIRECTORY"


def test_invalid_confidence_normalized(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    record = EcosystemRecord(
        "python",
        True,
        "INVALID",
        (),
        (),
        "detected",
    )

    result = generate_ecosystem_context(root, [record])

    assert result.ecosystems[0].confidence == "NONE"
    assert result.primary_ecosystem == "python"


def test_markers_are_sorted(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    record = EcosystemRecord(
        "python",
        True,
        "HIGH",
        (Path("z.py"), Path("a.py")),
        ("Z", "A"),
        "detected",
    )

    result = generate_ecosystem_context(root, [record])

    assert result.ecosystems[0].markers == (
        Path("a.py"),
        Path("z.py"),
    )
