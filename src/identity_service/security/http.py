"""One bounded synchronous HTTPX2 client shared for provider calls."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from types import MappingProxyType
from typing import Any

import httpx2

from identity_service.config import Settings
from identity_service.security.errors import (
    UpstreamNetworkError,
    UpstreamResponseTooLargeError,
    UpstreamTimeoutError,
)


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class _RejectAllCookiePolicy(DefaultCookiePolicy):
    """Reject provider cookie storage and transmission at the shared-client boundary."""

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


class UpstreamHttpClient:
    """A non-redirecting, non-proxying TLS-verifying shared client."""

    def __init__(
        self, settings: Settings, *, transport: httpx2.BaseTransport | None = None
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
        self._client = httpx2.Client(
            headers={"User-Agent": f"identity-service/{settings.service_version}"},
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
            limits=limits,
            transport=transport,
            cookies=CookieJar(policy=_RejectAllCookiePolicy()),
        )

    @property
    def max_response_bytes(self) -> int:
        return self._max_response_bytes

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> UpstreamResponse:
        request = self._client.build_request("GET", url, headers=headers)
        request.headers.pop("cookie", None)
        try:
            response = self._client.send(request, stream=True)
            try:
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=min(65_536, self._max_response_bytes)):
                    if len(chunk) > self._max_response_bytes - len(body):
                        raise UpstreamResponseTooLargeError("upstream response is oversized")
                    body.extend(chunk)
                return UpstreamResponse(
                    status_code=response.status_code,
                    headers=MappingProxyType(
                        {
                            name: response.headers[name]
                            for name in ("content-type", "cache-control", "retry-after")
                            if name in response.headers
                        }
                    ),
                    body=bytes(body),
                )
            finally:
                response.close()
        except httpx2.TimeoutException:
            raise UpstreamTimeoutError("upstream request timed out") from None
        except httpx2.HTTPError:
            raise UpstreamNetworkError("upstream transport failed") from None

    def close(self) -> None:
        try:
            self._client.cookies.clear()
        finally:
            self._client.close()
