from pathlib import Path

from sentinelshield.home_expander import expand_user_home


def test_tilde_expands_to_current_home():
    result = expand_user_home("~/project")

    assert result == str(Path.home() / "project")


def test_tilde_alone_expands():
    result = expand_user_home("~")

    assert result == str(Path.home())


def test_tilde_slash_expands():
    result = expand_user_home("~/")

    assert Path(result) == Path.home()


def test_absolute_path_is_unchanged():
    value = "/tmp/project"

    assert expand_user_home(value) == value


def test_relative_path_is_unchanged():
    value = "project"

    assert expand_user_home(value) == value


def test_other_user_home_is_not_expanded():
    value = "~otheruser/project"

    assert expand_user_home(value) == value


def test_none_is_unchanged():
    assert expand_user_home(None) is None


def test_path_object_is_expanded():
    result = expand_user_home(Path("~/project"))

    assert isinstance(result, Path)
    assert result == Path.home() / "project"


def test_unsupported_type_is_unchanged():
    value = 123

    assert expand_user_home(value) == value


def test_expansion_does_not_create_files(tmp_path):
    value = "~/sentinelshield-nonexistent-test-path"

    before = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    result = expand_user_home(value)

    after = sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
    )

    assert result == str(
        Path.home() / "sentinelshield-nonexistent-test-path"
    )
    assert before == after
