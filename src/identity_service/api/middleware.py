"""Request bounds, proxy trust, correlation, security headers, and access metrics."""

from __future__ import annotations

import contextvars
import ipaddress
import logging
import time
import uuid
from enum import StrEnum

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from identity_service.api.problems import status_problem
from identity_service.config import Settings
from identity_service.config.hosts import host_allowed, parse_host_header
from identity_service.observability.metrics import Metrics

request_id_context: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="unavailable"
)
SAFE_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
FORWARDED_HEADERS = {
    b"forwarded",
    b"x-forwarded-for",
    b"x-forwarded-host",
    b"x-forwarded-port",
    b"x-forwarded-proto",
}
CLIENT_DISCONNECTED_STATUS = 499


class BodyReadOutcome(StrEnum):
    COMPLETE = "complete"
    OVERSIZED = "oversized"
    DISCONNECTED = "disconnected"


def valid_request_id(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
    except ValueError, AttributeError:
        return False
    return parsed.version == 4 and str(parsed) == value


def get_request_id(scope: Scope) -> str:
    value = scope.get("identity_service.request_id")
    return value if isinstance(value, str) else request_id_context.get()


def _header_values(scope: Scope, name: bytes) -> list[str]:
    return [
        value.decode("latin-1") for key, value in scope.get("headers", []) if key.lower() == name
    ]


def _client_is_trusted(scope: Scope, settings: Settings) -> bool:
    client = scope.get("client")
    if client is None:
        return False
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        return False
    return any(address in network for network in settings.trusted_proxy_cidrs)


def _strip_untrusted_forwarding(scope: Scope) -> None:
    scope["headers"] = [
        (key, value)
        for key, value in scope.get("headers", [])
        if key.lower() not in FORWARDED_HEADERS
    ]


def _apply_trusted_forwarding(scope: Scope) -> bool:
    forwarded_proto = _header_values(scope, b"x-forwarded-proto")
    if len(forwarded_proto) == 1:
        scheme = forwarded_proto[0].split(",", maxsplit=1)[0].strip().lower()
        if scheme in {"http", "https"}:
            scope["scheme"] = scheme

    forwarded_host = _header_values(scope, b"x-forwarded-host")
    if forwarded_host:
        if len(forwarded_host) != 1 or parse_host_header(forwarded_host[0]) is None:
            return False
        headers = [
            (key, value) for key, value in scope.get("headers", []) if key.lower() != b"host"
        ]
        headers.append((b"host", forwarded_host[0].encode("latin-1")))
        scope["headers"] = headers

    forwarded_for = _header_values(scope, b"x-forwarded-for")
    if len(forwarded_for) == 1:
        candidate = forwarded_for[0].split(",", maxsplit=1)[0].strip()
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return True
        scope["client"] = (str(address), 0)
    return True


def _host_from_scope(scope: Scope) -> str | None:
    values = _header_values(scope, b"host")
    if len(values) != 1:
        return None
    return parse_host_header(values[0])


async def _bounded_body(receive: Receive, limit: int) -> tuple[BodyReadOutcome, bytes]:
    body = bytearray()
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return BodyReadOutcome.DISCONNECTED, b""
        if message["type"] != "http.request":
            continue
        body.extend(message.get("body", b""))
        if len(body) > limit:
            return BodyReadOutcome.OVERSIZED, b""
        if not message.get("more_body", False):
            return BodyReadOutcome.COMPLETE, bytes(body)


def _replay_body(body: bytes, original_receive: Receive) -> Receive:
    delivered = False

    async def receive() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await original_receive()

    return receive


class OperationalMiddleware:
    def __init__(self, app: ASGIApp, *, settings: Settings, metrics: Metrics) -> None:
        self.app = app
        self.settings = settings
        self.metrics = metrics
        self.logger = logging.getLogger("identity_service.http")

    def _security_headers(self, request_id: str, path: str) -> list[tuple[bytes, bytes]]:
        headers = [
            (b"x-request-id", request_id.encode()),
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"no-referrer"),
            (b"x-frame-options", b"DENY"),
        ]
        is_local_documentation = (
            self.settings.relaxed_local_environment
            and self.settings.enable_interactive_docs
            and path in {"/docs", "/redoc"}
        )
        if not is_local_documentation:
            headers.append(
                (
                    b"content-security-policy",
                    b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
                    b"form-action 'none'",
                )
            )
        if self.settings.deployed_environment:
            headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
        if path == "/v1/me":
            headers.append((b"cache-control", b"no-store"))
        return headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started_at = time.perf_counter()
        incoming_ids = _header_values(scope, b"x-request-id")
        request_id = (
            incoming_ids[0]
            if len(incoming_ids) == 1 and valid_request_id(incoming_ids[0])
            else str(uuid.uuid4())
        )
        scope["identity_service.request_id"] = request_id
        context_token = request_id_context.set(request_id)
        status = 500
        response_started = False
        force_connection_close = False

        forwarding_valid = len(_header_values(scope, b"host")) == 1
        if _client_is_trusted(scope, self.settings):
            forwarding_valid = forwarding_valid and _apply_trusted_forwarding(scope)
        else:
            _strip_untrusted_forwarding(scope)

        security_headers = self._security_headers(request_id, str(scope.get("path", "")))

        async def secure_send(message: Message) -> None:
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status = message["status"]
                protected_names = {name for name, _ in security_headers}
                headers = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() not in protected_names
                ]
                if force_connection_close:
                    headers = [
                        (key, value) for key, value in headers if key.lower() != b"connection"
                    ]
                    headers.append((b"connection", b"close"))
                headers.extend(security_headers)
                message["headers"] = headers
            await send(message)

        try:
            content_lengths = _header_values(scope, b"content-length")
            transfer_encodings = _header_values(scope, b"transfer-encoding")
            ambiguous_framing = (
                len(content_lengths) > 1
                or len(transfer_encodings) > 1
                or bool(content_lengths and transfer_encodings)
                or bool(transfer_encodings and transfer_encodings[0].strip().lower() != "chunked")
            )
            if ambiguous_framing:
                force_connection_close = True
                status = 400
                await status_problem(status, request_id)(scope, receive, secure_send)
                return
            if content_lengths:
                try:
                    declared_length = int(content_lengths[0])
                except ValueError:
                    declared_length = -1
                if declared_length < 0:
                    status = 400
                    await status_problem(status, request_id)(scope, receive, secure_send)
                    return
                if declared_length > self.settings.max_request_body_bytes:
                    status = 413
                    await status_problem(status, request_id)(scope, receive, secure_send)
                    return

            if not forwarding_valid or not host_allowed(
                _host_from_scope(scope), self.settings.allowed_hosts
            ):
                status = 400
                await status_problem(status, request_id)(scope, receive, secure_send)
                return

            body_outcome, body = await _bounded_body(receive, self.settings.max_request_body_bytes)
            if body_outcome is BodyReadOutcome.OVERSIZED:
                status = 413
                await status_problem(status, request_id)(scope, receive, secure_send)
                return
            if body_outcome is BodyReadOutcome.DISCONNECTED:
                status = CLIENT_DISCONNECTED_STATUS
                return

            scope["identity_service.body"] = body
            await self.app(scope, _replay_body(body, receive), secure_send)
        except Exception as error:
            if response_started:
                raise
            status = 500
            self.logger.error(
                "unexpected_request_error",
                extra={
                    "service": "identity-service",
                    "service_version": self.settings.service_version,
                    "environment": self.settings.app_env.value,
                    "request_id": request_id,
                    "outcome": "error",
                    "error_code": "internal_error",
                    "error_type": type(error).__name__,
                },
            )
            await status_problem(status, request_id)(scope, receive, secure_send)
        finally:
            duration = time.perf_counter() - started_at
            route = getattr(scope.get("route"), "path", "unmatched")
            method_value = str(scope.get("method", "OTHER")).upper()
            method = method_value if method_value in SAFE_METHODS else "OTHER"
            self.metrics.record_http(method, route, status, duration)
            self.logger.info(
                "request_complete",
                extra={
                    "service": "identity-service",
                    "service_version": self.settings.service_version,
                    "environment": self.settings.app_env.value,
                    "request_id": request_id,
                    "route": route,
                    "method": method,
                    "status_code": status,
                    "duration_ms": round(duration * 1000, 3),
                    "outcome": (
                        "disconnected"
                        if status == CLIENT_DISCONNECTED_STATUS
                        else "success"
                        if status < 500
                        else "error"
                    ),
                },
            )
            request_id_context.reset(context_token)
