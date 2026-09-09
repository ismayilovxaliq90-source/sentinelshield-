import pytest

from sentinelshield.parser_error_handling import (
    ParserErrorResult,
    handle_parser_error,
    parse_with_error_handling,
)


def test_successful_parser():
    result = handle_parser_error(lambda: {"name": "requests"})

    assert isinstance(result, ParserErrorResult)
    assert result.success is True
    assert result.value == {"name": "requests"}
    assert result.error_type is None
    assert result.error_message is None
    assert result.status == "PARSED"


@pytest.mark.parametrize(
    "error",
    [
        ValueError("invalid"),
        TypeError("wrong type"),
        KeyError("missing"),
        IndexError("out of range"),
    ],
)
def test_known_parser_errors_are_handled(error):
    def parser():
        raise error

    result = handle_parser_error(parser)

    assert result.success is False
    assert result.value is None
    assert result.error_type == type(error).__name__
    assert result.error_message == str(error)
    assert result.status == "PARSER_ERROR"


def test_unexpected_parser_error_is_handled():
    class ParserFailure(RuntimeError):
        pass

    def parser():
        raise ParserFailure("parser failed")

    result = handle_parser_error(parser)

    assert result.success is False
    assert result.value is None
    assert result.error_type == "ParserFailure"
    assert result.error_message == "parser failed"
    assert result.status == "PARSER_ERROR"


def test_invalid_parser_is_rejected():
    result = handle_parser_error(None)

    assert result.success is False
    assert result.value is None
    assert result.error_type == "INVALID_PARSER"
    assert result.error_message == "Parser must be callable"
    assert result.status == "PARSER_INVALID"


def test_integer_parser_is_rejected():
    result = handle_parser_error(123)

    assert result.success is False
    assert result.status == "PARSER_INVALID"


def test_parser_arguments_are_forwarded():
    def parser(name, version):
        return {
            "name": name,
            "version": version,
        }

    result = handle_parser_error(
        parser,
        "requests",
        "2.32.0",
    )

    assert result.success is True
    assert result.value == {
        "name": "requests",
        "version": "2.32.0",
    }


def test_parser_keyword_arguments_are_forwarded():
    def parser(*, name, version):
        return f"{name}=={version}"

    result = handle_parser_error(
        parser,
        name="requests",
        version="2.32.0",
    )

    assert result.success is True
    assert result.value == "requests==2.32.0"


def test_parser_returning_none_is_successful():
    result = handle_parser_error(lambda: None)

    assert result.success is True
    assert result.value is None
    assert result.status == "PARSED"


def test_parser_returning_empty_collection_is_successful():
    result = handle_parser_error(lambda: [])

    assert result.success is True
    assert result.value == []
    assert result.status == "PARSED"


def test_parser_error_does_not_escape():
    def parser():
        raise ValueError("bad manifest")

    result = handle_parser_error(parser)

    assert result.status == "PARSER_ERROR"


def test_exception_message_is_preserved():
    def parser():
        raise ValueError("invalid dependency syntax at line 7")

    result = handle_parser_error(parser)

    assert result.error_message == (
        "invalid dependency syntax at line 7"
    )


def test_exception_type_is_preserved():
    def parser():
        raise RuntimeError("failure")

    result = handle_parser_error(parser)

    assert result.error_type == "RuntimeError"


def test_keyboard_interrupt_is_not_swallowed():
    def parser():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        handle_parser_error(parser)


def test_system_exit_is_not_swallowed():
    def parser():
        raise SystemExit(1)

    with pytest.raises(SystemExit):
        handle_parser_error(parser)


def test_wrapper_function_works():
    result = parse_with_error_handling(
        lambda: ["requests", "urllib3"]
    )

    assert result.success is True
    assert result.value == ["requests", "urllib3"]
    assert result.status == "PARSED"


def test_wrapper_handles_errors():
    def parser():
        raise ValueError("invalid")

    result = parse_with_error_handling(parser)

    assert result.success is False
    assert result.status == "PARSER_ERROR"


def test_result_is_immutable():
    result = handle_parser_error(lambda: 1)

    with pytest.raises(AttributeError):
        result.success = False


def test_parser_is_called_once():
    calls = []

    def parser():
        calls.append(1)
        return "ok"

    result = handle_parser_error(parser)

    assert result.success is True
    assert calls == [1]


def test_error_result_has_no_partial_value():
    def parser():
        raise ValueError("failed")

    result = handle_parser_error(parser)

    assert result.value is None


def test_empty_error_message_is_allowed():
    def parser():
        raise ValueError()

    result = handle_parser_error(parser)

    assert result.success is False
    assert result.error_type == "ValueError"
    assert result.error_message == ""
    assert result.status == "PARSER_ERROR"


def test_parser_return_value_is_preserved_exactly():
    marker = object()

    result = handle_parser_error(lambda: marker)

    assert result.success is True
    assert result.value is marker


def test_parser_exception_does_not_change_status_to_parsed():
    def parser():
        raise RuntimeError("boom")

    result = handle_parser_error(parser)

    assert result.status != "PARSED"
    assert result.status == "PARSER_ERROR"


def test_result_type_on_error():
    result = handle_parser_error(
        lambda: (_ for _ in ()).throw(ValueError("x"))
    )

    assert isinstance(result, ParserErrorResult)
