from __future__ import annotations

from urllib.parse import quote

import pytest
from reference_bff.callback import (
    OAUTH_BINDING_COOKIE_NAME,
    CallbackDenied,
    CallbackSuccess,
    InvalidCallbackQueryError,
    InvalidOAuthBrowserBindingError,
    parse_callback_query,
    parse_oauth_browser_binding,
)

STATE = "A" * 43
BINDING = "B" * 43


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


def test_raw_cookie_parser_accepts_one_binding_and_unrelated_bounded_cookies() -> None:
    binding = parse_oauth_browser_binding(
        [
            (b"host", b"testserver"),
            (
                b"cookie",
                f"theme=dark; {OAUTH_BINDING_COOKIE_NAME}={BINDING}; padded=value==".encode(),
            ),
            (b"cookie", b"preference=compact"),
        ]
    )

    assert binding.transaction_id == BINDING
    assert BINDING not in repr(binding)


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"cookie", b"theme=dark")],
        [(b"cookie", b"")],
        [(b"cookie", f"{OAUTH_BINDING_COOKIE_NAME}={'A' * 42}".encode())],
        [(b"cookie", f"{OAUTH_BINDING_COOKIE_NAME}={'A' * 129}".encode())],
        [(b"cookie", f"{OAUTH_BINDING_COOKIE_NAME}={BINDING}\x7f".encode())],
        [(b"cookie", f"{OAUTH_BINDING_COOKIE_NAME}={BINDING};  theme=dark".encode())],
        [(b"cookie", f"{OAUTH_BINDING_COOKIE_NAME}={BINDING}; malformed".encode())],
        [
            (
                b"cookie",
                f"{OAUTH_BINDING_COOKIE_NAME}={BINDING}; "
                f"{OAUTH_BINDING_COOKIE_NAME}={BINDING}".encode(),
            )
        ],
        [
            (b"cookie", f"{OAUTH_BINDING_COOKIE_NAME}={BINDING}".encode()),
            (b"cookie", f"{OAUTH_BINDING_COOKIE_NAME}={BINDING}".encode()),
        ],
        [(b"cookie", b"unrelated=" + b"x" * 8192)],
    ],
)
def test_raw_cookie_parser_rejects_missing_malformed_control_duplicate_and_oversized_input(
    headers: list[tuple[bytes, bytes]],
) -> None:
    with pytest.raises(InvalidOAuthBrowserBindingError) as captured:
        parse_oauth_browser_binding(headers)

    assert BINDING not in repr(captured.value)
