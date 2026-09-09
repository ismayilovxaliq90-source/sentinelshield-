from sentinelshield.container_config_discovery import (
    discover_container_config,
)


def test_dockerfile(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM python:3.12\n")

    result = discover_container_config(root)

    assert result.found is True
    assert result.systems == ("docker",)


def test_compose(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "docker-compose.yml").write_text("services: {}\n")

    result = discover_container_config(root)

    assert result.found is True
    assert result.systems == ("docker-compose",)


def test_nested_dockerfile(tmp_path):
    root = tmp_path / "project"
    nested = root / "service"
    nested.mkdir(parents=True)
    (nested / "Dockerfile").write_text("FROM alpine\n")

    result = discover_container_config(root)

    assert result.found is True
    assert result.systems == ("docker",)


def test_multiple(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM alpine\n")
    (root / "compose.yaml").write_text("services: {}\n")

    result = discover_container_config(root)

    assert result.found is True
    assert result.systems == ("docker", "docker-compose")


def test_none():
    assert discover_container_config(None).reason == "PATH_IS_NONE"


def test_empty():
    assert discover_container_config(" ").reason == "PATH_IS_EMPTY"


def test_unsupported():
    assert discover_container_config(123).reason == "UNSUPPORTED_PATH_TYPE"


def test_no_config(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    result = discover_container_config(root)

    assert result.found is False
    assert result.reason == "CONTAINER_CONFIG_NOT_FOUND"


def test_no_execution(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Dockerfile").write_text("RUN echo MUST_NOT_EXECUTE\n")

    result = discover_container_config(root)

    assert result.found is True
