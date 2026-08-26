"""Duplicate-sensitive, bounded JSON parsing for untrusted OAuth data."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 512
MAX_JSON_STRING_LENGTH = 65_536
MAX_JSON_INTEGER_DIGITS = 20


class UnsafeJsonError(ValueError):
    """An upstream or JWT JSON document crossed a fixed safety boundary."""


def _object_without_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeJsonError("duplicate JSON member")
        result[key] = value
    return result


def _reject_float(_value: str) -> None:
    raise UnsafeJsonError("floating-point JSON values are not accepted")


def _bounded_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if not digits or len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise UnsafeJsonError("JSON integer is outside the bounded representation")
    return int(value)


def _reject_constant(_value: str) -> None:
    raise UnsafeJsonError("non-finite JSON values are not accepted")


def _validate_tree(value: Any, *, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise UnsafeJsonError("JSON nesting is excessive")
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING_LENGTH:
            raise UnsafeJsonError("JSON string is oversized")
        return 1
    if value is None or type(value) in {bool, int}:
        return 1
    if isinstance(value, list):
        items = 1 + sum(_validate_tree(item, depth=depth + 1) for item in value)
    elif isinstance(value, dict):
        items = 1
        for key, item in value.items():
            if len(key) > MAX_JSON_STRING_LENGTH:
                raise UnsafeJsonError("JSON member name is oversized")
            items += 1 + _validate_tree(item, depth=depth + 1)
    else:
        raise UnsafeJsonError("unsupported JSON value")
    if items > MAX_JSON_ITEMS:
        raise UnsafeJsonError("JSON document contains too many values")
    return items


def load_json(raw: bytes) -> Any:
    try:
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_float=_reject_float,
            parse_int=_bounded_integer,
            parse_constant=_reject_constant,
        )
    except UnicodeError, json.JSONDecodeError, RecursionError, OverflowError:
        raise UnsafeJsonError("malformed JSON") from None
    _validate_tree(value)
    return value


def load_json_object(raw: bytes) -> dict[str, Any]:
    value = load_json(raw)
    if type(value) is not dict:
        raise UnsafeJsonError("JSON document must be an object")
    return value
