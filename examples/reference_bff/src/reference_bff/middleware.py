"""Host, request-correlation, and browser-security response boundaries."""

from __future__ import annotations

import ipaddress
import re
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from reference_bff.problems import problem_response

REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
SECURITY_HEADERS = (
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"permissions-policy", b"camera=(), geolocation=(), microphone=()"),
)
REPLACED_HEADERS = {name for name, _ in SECURITY_HEADERS} | {b"x-request-id"}


def _parse_host(value: bytes) -> str | None:
    try:
        decoded = value.decode("ascii", errors="strict")
    except UnicodeError:
        return None
    if (
        decoded != decoded.strip()
        or not decoded
        or any(character.isspace() for character in decoded)
    ):
        return None
    if any(character in decoded for character in "/@\\?#[],") or decoded.count(":") > 1:
        return None
    host = decoded
    if ":" in decoded:
        host, raw_port = decoded.rsplit(":", maxsplit=1)
        if not raw_port.isascii() or not raw_port.isdecimal() or not 1 <= int(raw_port) <= 65_535:
            return None
    normalized = host.casefold().rstrip(".")
    try:
        return str(ipaddress.IPv4Address(normalized))
    except ipaddress.AddressValueError:
        if not normalized or len(normalized) > 253:
            return None
        if any(DNS_LABEL.fullmatch(label) is None for label in normalized.split(".")):
            return None
    return normalized


def _request_id(headers: list[tuple[bytes, bytes]]) -> str:
    values = [value for name, value in headers if name.lower() == b"x-request-id"]
    if len(values) == 1:
        try:
            decoded = values[0].decode("ascii", errors="strict")
        except UnicodeError:
            decoded = ""
        if REQUEST_ID.fullmatch(decoded) is not None:
            return decoded
    return uuid.uuid4().hex


def get_request_id(scope: Scope) -> str:
    state = scope.get("state")
    if isinstance(state, dict):
        value = state.get("request_id")
        if isinstance(value, str) and REQUEST_ID.fullmatch(value) is not None:
            return value
    return "unavailable"


class SecurityBoundaryMiddleware:
    def __init__(self, app: ASGIApp, *, allowed_hosts: list[str]) -> None:
        self._app = app
        self._allowed_hosts = frozenset(allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = list(scope.get("headers", []))
        request_id = _request_id(headers)
        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["request_id"] = request_id

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = [
                    (name, value)
                    for name, value in message.get("headers", [])
                    if name.lower() not in REPLACED_HEADERS
                    and not name.lower().startswith(b"access-control-")
                ]
                message["headers"] = [
                    *existing,
                    *SECURITY_HEADERS,
                    (b"x-request-id", request_id.encode("ascii")),
                ]
            await send(message)

        host_values = [value for name, value in headers if name.lower() == b"host"]
        host = _parse_host(host_values[0]) if len(host_values) == 1 else None
        if host not in self._allowed_hosts:
            response = problem_response(400, "invalid_host", request_id)
            await response(scope, receive, send_with_headers)
            return

        await self._app(scope, receive, send_with_headers)
