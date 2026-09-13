from pathlib import Path

import pytest

from sentinelshield.generated_file_impact_analysis import (
    GeneratedFileImpactAnalysisInput,
    analyze_generated_file_impact,
)


def test_added_file(tmp_path):
    root = tmp_path
    file = root / "generated.txt"
    file.write_text("generated", encoding="utf-8")

    result = analyze_generated_file_impact(
        GeneratedFileImpactAnalysisInput(
            project_root=root,
            generated_files=(Path("generated.txt"),),
            tracked_files=(),
            sensitive_paths=(),
        )
    )

    item = result.impacts[0]

    assert item.status == "ADDED"
    assert item.is_tracked is False
    assert item.is_sensitive is False
    assert item.sha256 is not None


def test_modified_tracked_file(tmp_path):
    root = tmp_path
    file = root / "generated.txt"
    file.write_text("changed", encoding="utf-8")

    result = analyze_generated_file_impact(
        GeneratedFileImpactAnalysisInput(
            project_root=root,
            generated_files=(Path("generated.txt"),),
            tracked_files=(Path("generated.txt"),),
            sensitive_paths=(),
        )
    )

    assert result.modified[0].status == "MODIFIED"
    assert result.modified[0].is_tracked is True


def test_sensitive_file(tmp_path):
    root = tmp_path
    sensitive = root / "secret.env"
    sensitive.write_text("secret", encoding="utf-8")

    result = analyze_generated_file_impact(
        GeneratedFileImpactAnalysisInput(
            project_root=root,
            generated_files=(Path("secret.env"),),
            tracked_files=(),
            sensitive_paths=(Path("secret.env"),),
        )
    )

    item = result.sensitive[0]

    assert item.status == "SENSITIVE"
    assert item.is_sensitive is True


def test_sensitive_subdirectory(tmp_path):
    root = tmp_path
    directory = root / "secrets"
    directory.mkdir()
    file = directory / "token.txt"
    file.write_text("secret", encoding="utf-8")

    result = analyze_generated_file_impact(
        GeneratedFileImpactAnalysisInput(
            project_root=root,
            generated_files=(Path("secrets/token.txt"),),
            tracked_files=(),
            sensitive_paths=(Path("secrets"),),
        )
    )

    assert result.sensitive[0].status == "SENSITIVE"


def test_unchanged_nonexistent_file(tmp_path):
    result = analyze_generated_file_impact(
        GeneratedFileImpactAnalysisInput(
            project_root=tmp_path,
            generated_files=(Path("missing.txt"),),
            tracked_files=(Path("missing.txt"),),
            sensitive_paths=(),
        )
    )

    assert result.unchanged[0].status == "UNCHANGED"


def test_untracked_generated_file(tmp_path):
    file = tmp_path / "output.txt"
    file.write_text("output", encoding="utf-8")

    result = analyze_generated_file_impact(
        GeneratedFileImpactAnalysisInput(
            project_root=tmp_path,
            generated_files=(Path("output.txt"),),
            tracked_files=(),
            sensitive_paths=(),
        )
    )

    assert len(result.untracked_generated_files) == 1


def test_sha256_is_deterministic(tmp_path):
    file = tmp_path / "output.txt"
    file.write_text("same-content", encoding="utf-8")

    request = GeneratedFileImpactAnalysisInput(
        project_root=tmp_path,
        generated_files=(Path("output.txt"),),
        tracked_files=(),
        sensitive_paths=(),
    )

    first = analyze_generated_file_impact(request)
    second = analyze_generated_file_impact(request)

    assert first.impacts[0].sha256 == second.impacts[0].sha256


def test_paths_are_normalized_relative_to_root(tmp_path):
    directory = tmp_path / "out"
    directory.mkdir()
    file = directory / "result.txt"
    file.write_text("x", encoding="utf-8")

    result = analyze_generated_file_impact(
        GeneratedFileImpactAnalysisInput(
            project_root=tmp_path,
            generated_files=(directory / "result.txt",),
            tracked_files=(),
            sensitive_paths=(),
        )
    )

    assert result.impacts[0].path == "out/result.txt"


def test_outside_project_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside-generated.txt"
    outside.write_text("x", encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="GENERATED_FILE_OUTSIDE_PROJECT_ROOT",
    ):
        analyze_generated_file_impact(
            GeneratedFileImpactAnalysisInput(
                project_root=tmp_path,
                generated_files=(outside,),
                tracked_files=(),
                sensitive_paths=(),
            )
        )


def test_invalid_input_is_rejected():
    with pytest.raises(
        TypeError,
        match="INPUT_MUST_BE_GENERATED_FILE_IMPACT_ANALYSIS_INPUT",
    ):
        analyze_generated_file_impact(None)
