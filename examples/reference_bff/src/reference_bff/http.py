"""Bounded async HTTP boundary for token, JWKS, and Identity calls."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from types import MappingProxyType
from typing import Any

import httpx2

from reference_bff.config import Settings


class UpstreamError(RuntimeError):
    """An upstream request could not produce a safe bounded response."""


class UpstreamUnavailableError(UpstreamError):
    """The upstream timed out or was unreachable."""


class UpstreamResponseError(UpstreamError):
    """The upstream response framing or body crossed the safety boundary."""


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


class _RejectAllCookiePolicy(DefaultCookiePolicy):
    def set_ok(self, cookie: Cookie, request: Any) -> bool:
        del cookie, request
        return False

    def return_ok(self, cookie: Cookie, request: Any) -> bool:
        del cookie, request
        return False

    def domain_return_ok(self, domain: str, request: Any) -> bool:
        del domain, request
        return False

    def path_return_ok(self, path: str, request: Any) -> bool:
        del path, request
        return False


class AsyncUpstreamClient:
    """TLS-verifying, non-proxying, non-redirecting, cookie-rejecting client."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        timeout = httpx2.Timeout(
            connect=settings.upstream_connect_timeout_seconds,
            read=settings.upstream_read_timeout_seconds,
            write=settings.upstream_write_timeout_seconds,
            pool=settings.upstream_pool_timeout_seconds,
        )
        limits = httpx2.Limits(
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=30.0,
        )
        self._max_response_bytes = settings.upstream_max_response_bytes
        self._client = httpx2.AsyncClient(
            headers={"User-Agent": f"reference-bff/{settings.service_version}"},
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
            limits=limits,
            transport=transport,
            cookies=CookieJar(policy=_RejectAllCookiePolicy()),
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: Mapping[str, str] | None = None,
    ) -> UpstreamResponse:
        request = self._client.build_request(method, url, headers=headers, data=data)
        request.headers.pop("cookie", None)
        try:
            response = await self._client.send(request, stream=True, follow_redirects=False)
            try:
                body = bytearray()
                async for chunk in response.aiter_bytes(
                    chunk_size=min(65_536, self._max_response_bytes)
                ):
                    if len(chunk) > self._max_response_bytes - len(body):
                        raise UpstreamResponseError("upstream response is oversized")
                    body.extend(chunk)
                safe_headers: dict[str, str] = {}
                for name in ("content-type", "cache-control", "retry-after"):
                    values = response.headers.get_list(name)
                    if len(values) > 1:
                        raise UpstreamResponseError("upstream response has duplicate metadata")
                    if values:
                        safe_headers[name] = values[0]
                return UpstreamResponse(
                    status_code=response.status_code,
                    headers=MappingProxyType(safe_headers),
                    body=bytes(body),
                )
            finally:
                await response.aclose()
                self._client.cookies.clear()
        except httpx2.TimeoutException:
            raise UpstreamUnavailableError("upstream request timed out") from None
        except httpx2.HTTPError:
            raise UpstreamUnavailableError("upstream transport failed") from None

    async def close(self) -> None:
        try:
            self._client.cookies.clear()
        finally:
            await self._client.aclose()


def json_media_type(headers: Mapping[str, str], *, allowed: frozenset[str]) -> bool:
    value = headers.get("content-type", "")
    if not value or len(value) > 256:
        return False
    parts = [part.strip() for part in value.split(";")]
    if parts[0].casefold() not in allowed:
        return False
    if len(parts) == 1:
        return True
    return len(parts) == 2 and parts[1].casefold() == "charset=utf-8"
