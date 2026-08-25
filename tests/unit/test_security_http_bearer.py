from __future__ import annotations

import io
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx2
import pytest

from identity_service.config import Settings
from identity_service.observability import configure_logging
from identity_service.security.bearer import parse_bearer_authorization
from identity_service.security.errors import (
    InvalidBearerSyntaxError,
    UpstreamNetworkError,
    UpstreamResponseTooLargeError,
    UpstreamTimeoutError,
)
from identity_service.security.http import UpstreamHttpClient


class ChunkStream(httpx2.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.closed = False

    def __iter__(self):  # type: ignore[no-untyped-def]
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


def test_bearer_parser_accepts_one_case_insensitive_compact_jwt() -> None:
    assert (
        parse_bearer_authorization(["bEaReR header.payload.signature"], max_token_bytes=100)
        == "header.payload.signature"
    )


@pytest.mark.parametrize(
    "values",
    [
        [],
        ["Bearer a.b.c", "Bearer d.e.f"],
        [""],
        ["Basic a.b.c"],
        ["Bearer"],
        ["Bearer  a.b.c"],
        ["Bearer a.b.c extra"],
        ["Bearer a.b.c,d.e.f"],
        ["Bearer a.b\tc"],
        ["Bearer a.b.c\r\nInjected: value"],
        ["Bearer no-periods"],
        ["Bearer too.many.periods.here"],
    ],
)
def test_bearer_parser_rejects_ambiguous_syntax(values: list[str]) -> None:
    with pytest.raises(InvalidBearerSyntaxError):
        parse_bearer_authorization(values, max_token_bytes=100)


def test_bearer_parser_enforces_byte_limit_before_provider_use() -> None:
    with pytest.raises(InvalidBearerSyntaxError):
        parse_bearer_authorization(["Bearer " + "a" * 50 + ".b.c"], max_token_bytes=20)


def test_shared_http_client_streams_bounded_response_and_sends_no_cookie(
    settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, str | None] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        observed["cookie"] = request.headers.get("cookie")
        observed["authorization"] = request.headers.get("authorization")
        observed["user_agent"] = request.headers.get("user-agent")
        return httpx2.Response(
            200,
            request=request,
            headers={"Content-Type": "application/json", "Set-Cookie": "unsafe=value"},
            content=b"{}",
        )

    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:9999")
    client = UpstreamHttpClient(settings_factory(), transport=httpx2.MockTransport(handler))
    try:
        first = client.get(
            "https://provider.invalid/one", headers={"Authorization": "Bearer redacted"}
        )
        second = client.get("https://provider.invalid/two")
    finally:
        client.close()
    assert first.body == b"{}"
    assert second.status_code == 200
    assert observed == {
        "cookie": None,
        "authorization": None,
        "user_agent": "identity-service/0.1.0",
    }


def test_shared_http_client_never_persists_single_multiple_or_malformed_cookies(
    settings_factory: Callable[..., Settings],
) -> None:
    observed_cookies: list[str | None] = []
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        observed_cookies.append(request.headers.get("cookie"))
        headers = [
            ("Content-Type", "application/json"),
            ("Set-Cookie", "provider_state=opaque; Path=/; Secure; HttpOnly"),
            ("Set-Cookie", "second_state=opaque; Path=/"),
            ("Set-Cookie", "malformed cookie value"),
        ]
        return httpx2.Response(200, request=request, headers=headers, content=b"{}")

    client = UpstreamHttpClient(settings_factory(), transport=httpx2.MockTransport(handler))
    try:
        first = client.get("https://provider.invalid/one")
        second = client.get("https://provider.invalid/two")
        assert "set-cookie" not in first.headers
        assert "set-cookie" not in second.headers
        assert list(client._client.cookies.jar) == []
    finally:
        client.close()
    assert calls == 2
    assert observed_cookies == [None, None]
    assert list(client._client.cookies.jar) == []


def test_shared_http_client_cookie_rejection_is_concurrency_safe(
    settings_factory: Callable[..., Settings],
) -> None:
    observed_cookies: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        observed_cookies.append(request.headers.get("cookie"))
        return httpx2.Response(
            200,
            request=request,
            headers={"Set-Cookie": "parallel_state=opaque; Path=/"},
            content=b"{}",
        )

    client = UpstreamHttpClient(settings_factory(), transport=httpx2.MockTransport(handler))
    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            statuses = list(
                executor.map(
                    lambda index: (
                        client.get(f"https://provider.invalid/parallel/{index}").status_code
                    ),
                    range(20),
                )
            )
        assert client.get("https://provider.invalid/later").status_code == 200
        assert list(client._client.cookies.jar) == []
    finally:
        client.close()
    assert statuses == [200] * 20
    assert observed_cookies == [None] * 21


def test_cookie_values_do_not_reach_logs_or_safe_transport_exceptions(
    settings_factory: Callable[..., Settings],
) -> None:
    stream = io.StringIO()
    configure_logging(settings_factory(log_format="json"), stream=stream)
    cookie_value = "test-cookie-value"

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/failure":
            raise httpx2.ConnectError(f"provider rejected Cookie={cookie_value}", request=request)
        return httpx2.Response(
            200,
            request=request,
            headers={"Set-Cookie": f"provider_state={cookie_value}; Path=/"},
            content=b"{}",
        )

    client = UpstreamHttpClient(settings_factory(), transport=httpx2.MockTransport(handler))
    try:
        client.get("https://provider.invalid/success")
        with pytest.raises(UpstreamNetworkError) as captured:
            client.get("https://provider.invalid/failure")
        logging.getLogger("identity_service.security.http").warning(
            "cookie boundary retained no provider state",
            extra={"cookie": cookie_value},
        )
    finally:
        client.close()
    assert cookie_value not in str(captured.value)
    assert cookie_value not in stream.getvalue()


def test_shared_http_client_returns_redirect_without_following(
    settings_factory: Callable[..., Settings],
) -> None:
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        return httpx2.Response(302, request=request, headers={"Location": "https://other.invalid"})

    client = UpstreamHttpClient(settings_factory(), transport=httpx2.MockTransport(handler))
    try:
        response = client.get("https://provider.invalid")
    finally:
        client.close()
    assert response.status_code == 302
    assert calls == 1


def test_shared_http_client_rejects_streamed_oversize(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(upstream_max_response_bytes=1024)
    transport = httpx2.MockTransport(
        lambda request: httpx2.Response(200, request=request, content=b"x" * 1025)
    )
    client = UpstreamHttpClient(settings, transport=transport)
    try:
        with pytest.raises(UpstreamResponseTooLargeError):
            client.get("https://provider.invalid")
    finally:
        client.close()


@pytest.mark.parametrize(
    ("chunks", "oversized"),
    [
        ([b"x" * 1025], True),
        ([b"x" * 600, b"y" * 425], True),
        ([b"x" * 512, b"", b"y" * 512], False),
        ([b"", b"{}", b""], False),
    ],
)
def test_shared_http_client_bounds_retained_bytes_before_append_and_closes_response(
    settings_factory: Callable[..., Settings], chunks: list[bytes], oversized: bool
) -> None:
    stream = ChunkStream(chunks)

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, request=request, stream=stream)

    client = UpstreamHttpClient(
        settings_factory(upstream_max_response_bytes=1024),
        transport=httpx2.MockTransport(handler),
    )
    try:
        if oversized:
            with pytest.raises(UpstreamResponseTooLargeError):
                client.get("https://provider.invalid")
        else:
            response = client.get("https://provider.invalid")
            assert response.body == b"".join(chunks)
            assert len(response.body) <= 1024
    finally:
        client.close()
    assert stream.closed is True


@pytest.mark.parametrize(
    ("provider_error", "expected"),
    [
        (httpx2.ReadTimeout("timeout"), UpstreamTimeoutError),
        (httpx2.ConnectError("network"), UpstreamNetworkError),
    ],
)
def test_shared_http_client_maps_transport_errors_without_detail(
    settings_factory: Callable[..., Settings],
    provider_error: httpx2.HTTPError,
    expected: type[Exception],
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        provider_error.request = request
        raise provider_error

    client = UpstreamHttpClient(settings_factory(), transport=httpx2.MockTransport(handler))
    try:
        with pytest.raises(expected) as captured:
            client.get("https://provider.invalid")
    finally:
        client.close()
    assert "provider.invalid" not in str(captured.value)
