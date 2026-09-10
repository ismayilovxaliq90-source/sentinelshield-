from pathlib import Path

import pytest

from sentinelshield.integrity_hash_regeneration import (
    IntegrityHashError,
    IntegrityHashRequest,
    IntegrityHashResult,
    calculate_sha256,
    regenerate_integrity_hashes,
    validate_integrity_hash,
    validate_integrity_result,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    return root


def test_sha256_is_deterministic(tmp_path):
    root = make_repo(tmp_path)
    target = root / "package-lock.json"
    target.write_text('{"lockfileVersion":3}', encoding="utf-8")

    first = calculate_sha256(target)
    second = calculate_sha256(target)

    assert first.digest == second.digest
    assert first.size == second.size
    assert first.algorithm == "sha256"


def test_sha256_changes_when_content_changes(tmp_path):
    root = make_repo(tmp_path)
    target = root / "package-lock.json"

    target.write_text("one", encoding="utf-8")
    first = calculate_sha256(target)

    target.write_text("two", encoding="utf-8")
    second = calculate_sha256(target)

    assert first.digest != second.digest


def test_multiple_files_are_hashed(tmp_path):
    root = make_repo(tmp_path)

    first = root / "package.json"
    second = root / "package-lock.json"

    first.write_text("{}", encoding="utf-8")
    second.write_text("{}", encoding="utf-8")

    result = regenerate_integrity_hashes(
        IntegrityHashRequest(
            repository_root=root,
            paths=(first, second),
        )
    )

    assert result.success is True
    assert len(result.hashes) == 2
    assert result.failed_paths == ()


def test_outside_repository_is_rejected(tmp_path):
    root = make_repo(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(IntegrityHashError):
        regenerate_integrity_hashes(
            IntegrityHashRequest(
                repository_root=root,
                paths=(outside,),
            )
        )


def test_symlink_is_rejected(tmp_path):
    root = make_repo(tmp_path)

    real = root / "real.json"
    link = root / "link.json"

    real.write_text("{}", encoding="utf-8")
    link.symlink_to(real)

    with pytest.raises(IntegrityHashError):
        calculate_sha256(link)


def test_directory_is_rejected(tmp_path):
    root = make_repo(tmp_path)
    directory = root / "directory"
    directory.mkdir()

    with pytest.raises(IntegrityHashError):
        calculate_sha256(directory)


def test_empty_path_list_is_rejected(tmp_path):
    root = make_repo(tmp_path)

    with pytest.raises(IntegrityHashError):
        regenerate_integrity_hashes(
            IntegrityHashRequest(
                repository_root=root,
                paths=(),
            )
        )


def test_unsupported_algorithm_is_rejected(tmp_path):
    root = make_repo(tmp_path)
    target = root / "package-lock.json"
    target.write_text("{}", encoding="utf-8")

    with pytest.raises(IntegrityHashError):
        regenerate_integrity_hashes(
            IntegrityHashRequest(
                repository_root=root,
                paths=(target,),
                algorithm="md5",
            )
        )


def test_size_limit_is_enforced(tmp_path):
    root = make_repo(tmp_path)
    target = root / "large.json"
    target.write_text("123456789", encoding="utf-8")

    with pytest.raises(IntegrityHashError):
        calculate_sha256(target, max_file_size=4)


def test_integrity_hash_validation():
    result = IntegrityHashResult(
        success=True,
        algorithm="sha256",
        hashes=(),
        failed_paths=(),
        error=None,
    )

    assert validate_integrity_result(result) is True


def test_result_serialization(tmp_path):
    root = make_repo(tmp_path)
    target = root / "package-lock.json"
    target.write_text("{}", encoding="utf-8")

    result = regenerate_integrity_hashes(
        IntegrityHashRequest(
            repository_root=root,
            paths=(target,),
        )
    )

    data = result.to_dict()

    assert data["success"] is True
    assert data["algorithm"] == "sha256"
    assert len(data["hashes"]) == 1
    assert data["hashes"][0]["algorithm"] == "sha256"


def test_invalid_digest_is_rejected(tmp_path):
    target = tmp_path / "x"

    integrity = type(
        "FakeIntegrity",
        (),
        {
            "algorithm": "sha256",
            "digest": "bad",
            "size": 1,
        },
    )()

    assert validate_integrity_hash(integrity) is False
