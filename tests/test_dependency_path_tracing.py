from sentinelshield.dependency_path_tracing import (
    DependencyPath,
    DependencyPathTracingResult,
    trace_dependency_paths,
)


def test_direct_path():
    result = trace_dependency_paths(
        [("app", "requests")],
        "app",
        "requests",
    )

    assert result.traced is True
    assert result.status == "PATH_FOUND"
    assert result.paths == (
        DependencyPath(
            "app",
            "requests",
            ("app", "requests"),
        ),
    )


def test_transitive_path():
    result = trace_dependency_paths(
        [
            ("app", "requests"),
            ("requests", "urllib3"),
        ],
        "app",
        "urllib3",
    )

    assert result.paths[0].path == (
        "app",
        "requests",
        "urllib3",
    )


def test_multiple_paths():
    result = trace_dependency_paths(
        [
            ("app", "a"),
            ("app", "b"),
            ("a", "target"),
            ("b", "target"),
        ],
        "app",
        "target",
    )

    assert len(result.paths) == 2
    assert [p.path for p in result.paths] == [
        ("app", "a", "target"),
        ("app", "b", "target"),
    ]


def test_path_not_found():
    result = trace_dependency_paths(
        [("app", "requests")],
        "app",
        "urllib3",
    )

    assert result.traced is True
    assert result.status == "PATH_NOT_FOUND"
    assert result.paths == ()


def test_same_source_and_target():
    result = trace_dependency_paths([], "app", "app")

    assert result.status == "PATH_FOUND"
    assert result.paths[0].path == ("app",)


def test_cycle_does_not_loop():
    result = trace_dependency_paths(
        [
            ("app", "a"),
            ("a", "b"),
            ("b", "a"),
        ],
        "app",
        "missing",
    )

    assert result.traced is True
    assert result.status == "PATH_NOT_FOUND"


def test_duplicate_edges_do_not_duplicate_paths():
    result = trace_dependency_paths(
        [
            ("app", "requests"),
            ("app", "requests"),
        ],
        "app",
        "requests",
    )

    assert len(result.paths) == 1


def test_dict_edges():
    result = trace_dependency_paths(
        [
            {"parent": "app", "child": "requests"},
            {"parent": "requests", "child": "urllib3"},
        ],
        "app",
        "urllib3",
    )

    assert result.paths[0].path == (
        "app",
        "requests",
        "urllib3",
    )


def test_none_edges():
    result = trace_dependency_paths(None, "app", "x")

    assert result.traced is False
    assert result.status == "EDGES_IS_NONE"


def test_string_edges():
    result = trace_dependency_paths("app", "app", "x")

    assert result.traced is False
    assert result.status == "UNSUPPORTED_EDGE_COLLECTION"


def test_invalid_source():
    result = trace_dependency_paths([], "", "x")

    assert result.traced is False
    assert result.status == "INVALID_SOURCE"


def test_invalid_target():
    result = trace_dependency_paths([], "app", "")

    assert result.traced is False
    assert result.status == "INVALID_TARGET"


def test_invalid_parent():
    result = trace_dependency_paths(
        [(None, "x")],
        "app",
        "x",
    )

    assert result.status == "INVALID_PARENT"


def test_invalid_child():
    result = trace_dependency_paths(
        [("app", None)],
        "app",
        "x",
    )

    assert result.status == "INVALID_CHILD"


def test_whitespace_is_normalized():
    result = trace_dependency_paths(
        [(" app ", " requests ")],
        " app ",
        " requests ",
    )

    assert result.paths[0].path == (
        "app",
        "requests",
    )


def test_result_type():
    result = trace_dependency_paths(
        [("app", "x")],
        "app",
        "x",
    )

    assert isinstance(result, DependencyPathTracingResult)


def test_path_is_tuple():
    result = trace_dependency_paths(
        [("app", "x")],
        "app",
        "x",
    )

    assert isinstance(result.paths[0].path, tuple)


def test_input_is_not_modified():
    edges = [
        ("app", "b"),
        ("app", "a"),
    ]
    original = list(edges)

    trace_dependency_paths(edges, "app", "a")

    assert edges == original


def test_deterministic_order():
    result = trace_dependency_paths(
        [
            ("app", "z"),
            ("app", "a"),
            ("z", "target"),
            ("a", "target"),
        ],
        "app",
        "target",
    )

    assert [p.path for p in result.paths] == [
        ("app", "a", "target"),
        ("app", "z", "target"),
    ]
