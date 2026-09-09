from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class ParserErrorResult:
    success: bool
    value: Any
    error_type: Optional[str]
    error_message: Optional[str]
    status: str


def handle_parser_error(
    parser: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> ParserErrorResult:
    """
    Execute an already-supplied parser safely.

    Parser errors are converted into structured results.
    No filesystem or package-manager operation is performed here.
    """

    if not callable(parser):
        return ParserErrorResult(
            success=False,
            value=None,
            error_type="INVALID_PARSER",
            error_message="Parser must be callable",
            status="PARSER_INVALID",
        )

    try:
        value = parser(*args, **kwargs)

    except (KeyboardInterrupt, SystemExit):
        raise

    except (ValueError, TypeError, KeyError, IndexError) as error:
        return ParserErrorResult(
            success=False,
            value=None,
            error_type=type(error).__name__,
            error_message=str(error),
            status="PARSER_ERROR",
        )

    except Exception as error:
        return ParserErrorResult(
            success=False,
            value=None,
            error_type=type(error).__name__,
            error_message=str(error),
            status="PARSER_ERROR",
        )

    return ParserErrorResult(
        success=True,
        value=value,
        error_type=None,
        error_message=None,
        status="PARSED",
    )


def parse_with_error_handling(
    parser: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> ParserErrorResult:
    return handle_parser_error(parser, *args, **kwargs)
