from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from starlette.types import Message, Scope

from identity_service.api.middleware import OperationalMiddleware
from identity_service.config import Settings
from identity_service.observability.metrics import Metrics


def _http_scope(
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] = ("198.51.100.10", 40000),
) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/health/live",
        "raw_path": b"/health/live",
        "query_string": b"",
        "root_path": "",
        "headers": headers or [(b"host", b"testserver")],
        "client": client,
        "server": ("testserver", 80),
    }


def _exercise_body_messages(
    settings: Settings,
    messages: list[Message],
    *,
    downstream_reads: int = 1,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[bool, list[Message], list[Message]]:
    downstream_called = False
    replayed: list[Message] = []
    sent: list[Message] = []
    incoming = iter(messages)

    async def downstream(scope: Scope, receive: Any, send: Any) -> None:
        nonlocal downstream_called
        del scope
        downstream_called = True
        for _ in range(downstream_reads):
            replayed.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        return next(incoming)  # type: ignore[return-value]

    async def send(message: Message) -> None:
        sent.append(message)

    middleware = OperationalMiddleware(downstream, settings=settings, metrics=Metrics())
    asyncio.run(middleware(_http_scope(headers=headers), receive, send))
    return downstream_called, replayed, sent


def test_streamed_body_is_bounded_without_content_length(
    settings_factory: Callable[..., Settings],
) -> None:
    downstream_called = False
    messages = iter(
        [
            {"type": "http.request", "body": b"12345678", "more_body": True},
            {"type": "http.request", "body": b"901234567", "more_body": False},
        ]
    )
    sent: list[Message] = []

    async def downstream(scope: Scope, receive: Any, send: Any) -> None:
        nonlocal downstream_called
        downstream_called = True

    async def receive() -> Message:
        return next(messages)  # type: ignore[return-value]

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/health/live",
        "raw_path": b"/health/live",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("198.51.100.10", 40000),
        "server": ("testserver", 80),
    }
    middleware = OperationalMiddleware(
        downstream,
        settings=settings_factory(max_request_body_bytes=16),
        metrics=Metrics(),
    )
    asyncio.run(middleware(scope, receive, send))

    assert not downstream_called
    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 413
    assert any(key == b"x-request-id" for key, _ in start["headers"])


def test_trusted_proxy_headers_are_applied_only_for_configured_peer(
    settings_factory: Callable[..., Settings],
) -> None:
    observed: dict[str, object] = {}
    sent: list[Message] = []

    async def downstream(scope: Scope, receive: Any, send: Any) -> None:
        observed.update(
            scheme=scope["scheme"],
            client=scope["client"],
            headers=dict(scope["headers"]),
        )
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    received = False

    async def receive() -> Message:
        nonlocal received
        if received:
            return {"type": "http.request", "body": b"", "more_body": False}
        received = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/health/live",
        "raw_path": b"/health/live",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"internal.invalid"),
            (b"x-forwarded-proto", b"https"),
            (b"x-forwarded-host", b"testserver"),
            (b"x-forwarded-for", b"203.0.113.10"),
        ],
        "client": ("127.0.0.1", 40000),
        "server": ("internal.invalid", 80),
    }
    middleware = OperationalMiddleware(
        downstream,
        settings=settings_factory(trusted_proxy_cidrs=["127.0.0.0/8"]),
        metrics=Metrics(),
    )
    asyncio.run(middleware(scope, receive, send))
    assert observed["scheme"] == "https"
    assert observed["client"] == ("203.0.113.10", 0)
    assert observed["headers"][b"host"] == b"testserver"  # type: ignore[index]
    assert any(message.get("status") == 204 for message in sent)


def test_complete_empty_body_is_replayed(
    settings_factory: Callable[..., Settings],
) -> None:
    called, replayed, sent = _exercise_body_messages(
        settings_factory(),
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    assert called
    assert replayed == [{"type": "http.request", "body": b"", "more_body": False}]
    assert any(message.get("status") == 204 for message in sent)


def test_complete_multichunk_body_is_replayed_as_one_complete_body(
    settings_factory: Callable[..., Settings],
) -> None:
    called, replayed, _ = _exercise_body_messages(
        settings_factory(),
        [
            {"type": "http.request", "body": b"first-", "more_body": True},
            {"type": "http.request", "body": b"second", "more_body": False},
        ],
    )
    assert called
    assert replayed == [{"type": "http.request", "body": b"first-second", "more_body": False}]


def test_oversized_body_remains_413_and_never_reaches_downstream(
    settings_factory: Callable[..., Settings],
) -> None:
    called, replayed, sent = _exercise_body_messages(
        settings_factory(max_request_body_bytes=4),
        [{"type": "http.request", "body": b"12345", "more_body": False}],
    )
    assert not called
    assert replayed == []
    assert (
        next(message for message in sent if message["type"] == "http.response.start")["status"]
        == 413
    )


def test_disconnect_before_any_complete_body_never_reaches_downstream(
    settings_factory: Callable[..., Settings],
) -> None:
    called, replayed, sent = _exercise_body_messages(
        settings_factory(),
        [{"type": "http.disconnect"}],
    )
    assert not called
    assert replayed == []
    assert sent == []


def test_disconnect_after_partial_body_never_reaches_downstream(
    settings_factory: Callable[..., Settings],
) -> None:
    called, replayed, sent = _exercise_body_messages(
        settings_factory(),
        [
            {"type": "http.request", "body": b"partial", "more_body": True},
            {"type": "http.disconnect"},
        ],
    )
    assert not called
    assert replayed == []
    assert sent == []


def test_disconnect_after_complete_body_remains_visible_after_replay(
    settings_factory: Callable[..., Settings],
) -> None:
    called, replayed, sent = _exercise_body_messages(
        settings_factory(),
        [
            {"type": "http.request", "body": b"complete", "more_body": False},
            {"type": "http.disconnect"},
        ],
        downstream_reads=2,
    )
    assert called
    assert replayed == [
        {"type": "http.request", "body": b"complete", "more_body": False},
        {"type": "http.disconnect"},
    ]
    assert any(message.get("status") == 204 for message in sent)


@pytest.mark.parametrize(
    "framing_headers",
    [
        [(b"content-length", b"0"), (b"content-length", b"1")],
        [(b"content-length", b"0"), (b"transfer-encoding", b"chunked")],
        [(b"transfer-encoding", b"chunked"), (b"transfer-encoding", b"chunked")],
        [(b"transfer-encoding", b"gzip")],
    ],
)
def test_ambiguous_request_framing_is_rejected_and_closes_connection(
    settings_factory: Callable[..., Settings], framing_headers: list[tuple[bytes, bytes]]
) -> None:
    called, replayed, sent = _exercise_body_messages(
        settings_factory(),
        [{"type": "http.request", "body": b"", "more_body": False}],
        headers=[(b"host", b"testserver"), *framing_headers],
    )
    assert not called
    assert replayed == []
    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 400
    assert (b"connection", b"close") in start["headers"]


@pytest.mark.parametrize(
    "headers",
    [
        [(b"host", b"testserver"), (b"host", b"testserver")],
        [
            (b"host", b"internal.invalid"),
            (b"x-forwarded-host", b"testserver#fragment"),
        ],
        [
            (b"host", b"internal.invalid"),
            (b"x-forwarded-host", b"testserver"),
            (b"x-forwarded-host", b"other.invalid"),
        ],
    ],
)
def test_duplicate_or_malformed_direct_and_forwarded_hosts_are_rejected(
    settings_factory: Callable[..., Settings], headers: list[tuple[bytes, bytes]]
) -> None:
    downstream_called = False
    sent: list[Message] = []

    async def downstream(scope: Scope, receive: Any, send: Any) -> None:
        nonlocal downstream_called
        del scope, receive, send
        downstream_called = True

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    middleware = OperationalMiddleware(
        downstream,
        settings=settings_factory(trusted_proxy_cidrs=["127.0.0.0/8"]),
        metrics=Metrics(),
    )
    asyncio.run(
        middleware(
            _http_scope(headers=headers, client=("127.0.0.1", 40000)),
            receive,
            send,
        )
    )
    assert not downstream_called
    assert (
        next(message for message in sent if message["type"] == "http.response.start")["status"]
        == 400
    )
