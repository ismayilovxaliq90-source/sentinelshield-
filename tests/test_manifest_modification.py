import json

import pytest

from sentinelshield.manifest_modification import (
    ManifestModificationError,
    ManifestModificationPolicy,
    modify_manifest,
    validate_manifest_modification,
)


def test_requirements_dependency_is_modified(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "requests==2.31.0\nurllib3==2.0.7\n",
        encoding="utf-8",
    )

    result = modify_manifest(
        repository_root=tmp_path,
        manifest=manifest,
        dependency="requests",
        new_value="==2.32.5",
    )

    assert result.modified is True
    assert result.changes == 1
    assert result.old_value == "==2.31.0"
    assert result.new_value == "==2.32.5"
    assert "requests==2.32.5" in manifest.read_text()
    assert "urllib3==2.0.7" in manifest.read_text()


def test_json_dependency_is_modified(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps(
            {
                "dependencies": {
                    "lodash": "^4.17.20",
                    "express": "^4.18.0",
                }
            }
        ),
        encoding="utf-8",
    )

    result = modify_manifest(
        repository_root=tmp_path,
        manifest=manifest,
        dependency="lodash",
        new_value="^4.17.21",
    )

    document = json.loads(manifest.read_text())

    assert result.changes == 1
    assert result.old_value == "^4.17.20"
    assert document["dependencies"]["lodash"] == "^4.17.21"
    assert document["dependencies"]["express"] == "^4.18.0"


def test_duplicate_requirements_target_is_rejected(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "requests==2.31.0\nrequests==2.32.0\n",
        encoding="utf-8",
    )

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=tmp_path,
            manifest=manifest,
            dependency="requests",
            new_value="==2.32.5",
        )


def test_missing_dependency_is_rejected(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "urllib3==2.0.7\n",
        encoding="utf-8",
    )

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=tmp_path,
            manifest=manifest,
            dependency="requests",
            new_value="==2.32.5",
        )


def test_outside_repository_is_rejected(tmp_path):
    repository = tmp_path / "repo"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()

    manifest = outside / "requirements.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=repository,
            manifest=manifest,
            dependency="requests",
            new_value="==2.32.5",
        )


def test_disallowed_manifest_is_rejected(tmp_path):
    manifest = tmp_path / "random.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=tmp_path,
            manifest=manifest,
            dependency="requests",
            new_value="==2.32.5",
        )


def test_dependency_path_traversal_is_rejected(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=tmp_path,
            manifest=manifest,
            dependency="../requests",
            new_value="==2.32.5",
        )


def test_nul_dependency_is_rejected(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=tmp_path,
            manifest=manifest,
            dependency="requests\x00evil",
            new_value="==2.32.5",
        )


def test_validation_accepts_valid_result(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")

    result = modify_manifest(
        repository_root=tmp_path,
        manifest=manifest,
        dependency="requests",
        new_value="==2.32.5",
    )

    assert validate_manifest_modification(result) is True


def test_symlink_manifest_is_rejected(tmp_path):
    repository = tmp_path / "repo"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()

    target = outside / "requirements.txt"
    target.write_text("requests==2.31.0\n", encoding="utf-8")

    link = repository / "requirements.txt"
    link.symlink_to(target)

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=repository,
            manifest=link,
            dependency="requests",
            new_value="==2.32.5",
        )


def test_policy_type_is_checked(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=tmp_path,
            manifest=manifest,
            dependency="requests",
            new_value="==2.32.5",
            policy=object(),
        )


def test_json_duplicate_dependency_sections_are_rejected(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "^4.17.20"},
                "devDependencies": {"lodash": "^4.17.20"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ManifestModificationError):
        modify_manifest(
            repository_root=tmp_path,
            manifest=manifest,
            dependency="lodash",
            new_value="^4.17.21",
        )


def test_original_hash_differs_after_change(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")

    result = modify_manifest(
        repository_root=tmp_path,
        manifest=manifest,
        dependency="requests",
        new_value="==2.32.5",
    )

    assert result.original_sha256 != result.final_sha256
