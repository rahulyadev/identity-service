from __future__ import annotations

from urllib.parse import quote

import pytest
from reference_bff.callback import (
    CallbackDenied,
    CallbackSuccess,
    InvalidCallbackQueryError,
    parse_callback_query,
)

STATE = "A" * 43


def parse(query: bytes) -> CallbackSuccess | CallbackDenied:
    return parse_callback_query(
        query,
        max_query_bytes=8192,
        max_code_bytes=4096,
        max_error_bytes=128,
    )


def test_callback_accepts_exact_success_and_denial_shapes() -> None:
    encoded_code = quote("synthetic/code=value", safe="-._~")
    success = parse(f"code={encoded_code}&state={STATE}".encode())
    denied = parse(f"error=access_denied&state={STATE}".encode())

    assert isinstance(success, CallbackSuccess)
    assert success.code == "synthetic/code=value"
    assert success.state == STATE
    assert isinstance(denied, CallbackDenied)
    assert denied.provider_error == "access_denied"
    assert denied.state == STATE
    assert "synthetic/code" not in repr(success)
    assert STATE not in repr(success)
    assert "access_denied" not in repr(denied)


@pytest.mark.parametrize(
    "query",
    [
        b"",
        f"state={STATE}".encode(),
        f"code=one&state={STATE}&error=access_denied".encode(),
        f"code=one&code=two&state={STATE}".encode(),
        f"code=one&state={STATE}&state={STATE}".encode(),
        f"error=access_denied&error=other&state={STATE}".encode(),
        f"code=one&state={STATE}&error_description=text".encode(),
        f"code=one&state={STATE}&unknown=value".encode(),
        f"code=one&&state={STATE}".encode(),
        f"code&state={STATE}".encode(),
        f"code=one=two&state={STATE}".encode(),
    ],
)
def test_callback_rejects_missing_duplicate_mixed_and_unknown_parameters(query: bytes) -> None:
    with pytest.raises(InvalidCallbackQueryError):
        parse(query)


@pytest.mark.parametrize(
    "query",
    [
        f"code=synthetic+code&state={STATE}".encode(),
        f"code=%2f&state={STATE}".encode(),
        f"code=%GG&state={STATE}".encode(),
        f"code=%FF&state={STATE}".encode(),
        f"code=one&state={'A' * 42}".encode(),
        f"code=one&state={'A' * 129}".encode(),
        f"error=access%5fdenied&state={STATE}".encode(),
        f"error=1invalid&state={STATE}".encode(),
    ],
)
def test_callback_rejects_noncanonical_encoding_and_invalid_security_values(
    query: bytes,
) -> None:
    with pytest.raises(InvalidCallbackQueryError):
        parse(query)


def test_callback_enforces_predecode_and_per_value_size_bounds() -> None:
    with pytest.raises(InvalidCallbackQueryError):
        parse_callback_query(
            b"code=one&state=" + STATE.encode(),
            max_query_bytes=16,
            max_code_bytes=4096,
            max_error_bytes=128,
        )
    with pytest.raises(InvalidCallbackQueryError):
        parse_callback_query(
            b"code=" + b"x" * 129 + b"&state=" + STATE.encode(),
            max_query_bytes=8192,
            max_code_bytes=128,
            max_error_bytes=128,
        )
    with pytest.raises(InvalidCallbackQueryError):
        parse_callback_query(
            b"error=" + b"x" * 129 + b"&state=" + STATE.encode(),
            max_query_bytes=8192,
            max_code_bytes=4096,
            max_error_bytes=128,
        )
