from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pytest
from reference_bff.config import Settings
from reference_bff.http import (
    AsyncUpstreamClient,
    UpstreamResponseError,
    UpstreamUnavailableError,
    json_media_type,
)


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def client(
    settings: Settings,
    handler: Callable[[httpx2.Request], httpx2.Response],
) -> AsyncUpstreamClient:
    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(handler))
    return AsyncUpstreamClient(settings, transport=transport)


def test_upstream_never_redirects_or_persists_provider_cookies(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(
            302,
            request=request,
            headers={
                "Location": "http://127.0.0.1:9000/other",
                "Set-Cookie": "provider=forbidden; Path=/",
                "Content-Type": "application/json",
            },
            content=b"{}",
        )

    upstream = client(bff_settings_factory(), handler)

    async def scenario() -> None:
        first = await upstream.request("GET", "http://127.0.0.1:9000/first")
        second = await upstream.request("GET", "http://127.0.0.1:9000/second")
        assert first.status_code == second.status_code == 302
        await upstream.close()

    run(scenario())
    assert len(requests) == 2
    assert all("cookie" not in request.headers for request in requests)


def test_upstream_enforces_body_and_duplicate_metadata_bounds(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    oversized = client(
        bff_settings_factory(upstream_max_response_bytes=1024),
        lambda request: httpx2.Response(200, request=request, content=b"x" * 1025),
    )
    duplicated = client(
        bff_settings_factory(),
        lambda request: httpx2.Response(
            200,
            request=request,
            headers=[("Content-Type", "application/json"), ("Content-Type", "text/plain")],
            content=b"{}",
        ),
    )

    async def scenario() -> None:
        with pytest.raises(UpstreamResponseError):
            await oversized.request("GET", "http://127.0.0.1:9000/oversized")
        with pytest.raises(UpstreamResponseError):
            await duplicated.request("GET", "http://127.0.0.1:9000/duplicated")
        await oversized.close()
        await duplicated.close()

    run(scenario())


@pytest.mark.parametrize("error_type", [httpx2.ReadTimeout, httpx2.ConnectError])
def test_upstream_maps_timeout_and_network_errors_without_details(
    bff_settings_factory: Callable[..., Settings],
    error_type: type[httpx2.RequestError],
) -> None:
    def fail(request: httpx2.Request) -> httpx2.Response:
        raise error_type("synthetic upstream detail", request=request)

    upstream = client(bff_settings_factory(), fail)

    async def scenario() -> None:
        with pytest.raises(UpstreamUnavailableError) as captured:
            await upstream.request("GET", "http://127.0.0.1:9000/fail")
        assert "127.0.0.1" not in str(captured.value)
        await upstream.close()

    run(scenario())


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        ("application/json", True),
        ("APPLICATION/JSON; CHARSET=UTF-8", True),
        ("application/json; charset=latin1", False),
        ("text/json", False),
        ("", False),
    ],
)
def test_json_media_type_is_exact(content_type: str, expected: bool) -> None:
    assert (
        json_media_type(
            {"content-type": content_type},
            allowed=frozenset({"application/json"}),
        )
        is expected
    )
