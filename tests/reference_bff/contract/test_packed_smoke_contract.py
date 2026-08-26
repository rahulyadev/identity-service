from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest

from examples.reference_bff.scripts import container_smoke

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = ROOT / "compose.yaml"


def bff_environment() -> dict[str, str]:
    environment: dict[str, str] = {}
    in_bff = False
    in_environment = False
    for line in COMPOSE_PATH.read_text(encoding="utf-8").splitlines():
        if line == "  bff:":
            in_bff = True
            continue
        if in_bff and line and not line.startswith(" "):
            break
        if in_bff and line == "    environment:":
            in_environment = True
            continue
        if in_environment:
            if not line.startswith("      "):
                break
            name, value = line.strip().split(": ", 1)
            environment[name] = value
    return environment


def test_fixture_uses_os_assigned_loopback_port() -> None:
    class Handler(BaseHTTPRequestHandler):
        pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    try:
        origin = urlsplit(container_smoke.bound_fixture_origin(server))
        assert origin.scheme == "http"
        assert origin.hostname == "127.0.0.1"
        assert origin.port == server.server_address[1]
        assert origin.port != 0
    finally:
        server.server_close()


@pytest.mark.parametrize("previous_origin", [None, "", "http://127.0.0.1:49000"])
def test_main_propagates_bound_origin_and_restores_environment(
    monkeypatch: pytest.MonkeyPatch, previous_origin: str | None
) -> None:
    events: list[object] = []
    fixture = SimpleNamespace(issuer="")

    class FakeServer:
        server_address = ("127.0.0.1", 43_210)

        def __init__(self, address: tuple[str, int], handler: Any) -> None:
            del handler
            events.append(("bind", address))

        def serve_forever(self) -> None:
            events.append("serve_forever")

        def shutdown(self) -> None:
            events.append("shutdown")

        def server_close(self) -> None:
            events.append("server_close")

    class FakeThread:
        def __init__(self, *, target: Any, daemon: bool) -> None:
            assert daemon is True
            self.target = target

        def start(self) -> None:
            events.append("thread_start")
            self.target()

        def join(self, *, timeout: int) -> None:
            events.append(("thread_join", timeout))

    def fake_run(*arguments: str, check: bool = True) -> str:
        events.append(("run", arguments, check))
        if arguments[:2] == ("compose", "up"):
            assert os.environ[container_smoke.FIXTURE_ORIGIN_ENVIRONMENT] == (
                "http://127.0.0.1:43210"
            )
            assert fixture.issuer == "http://127.0.0.1:43210/test-pool"
            raise RuntimeError("bounded setup failure")
        assert arguments == ("compose", "down", "--volumes", "--remove-orphans")
        assert check is False
        return ""

    if previous_origin is None:
        monkeypatch.delenv(container_smoke.FIXTURE_ORIGIN_ENVIRONMENT, raising=False)
    else:
        monkeypatch.setenv(container_smoke.FIXTURE_ORIGIN_ENVIRONMENT, previous_origin)
    monkeypatch.setattr(container_smoke, "FixtureState", lambda: fixture)
    monkeypatch.setattr(container_smoke, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(container_smoke.threading, "Thread", FakeThread)
    monkeypatch.setattr(container_smoke, "run", fake_run)

    with pytest.raises(RuntimeError, match="bounded setup failure"):
        container_smoke.main()

    if previous_origin is None:
        assert container_smoke.FIXTURE_ORIGIN_ENVIRONMENT not in os.environ
    else:
        assert os.environ[container_smoke.FIXTURE_ORIGIN_ENVIRONMENT] == previous_origin
    assert events == [
        ("bind", ("127.0.0.1", 0)),
        "thread_start",
        "serve_forever",
        ("run", ("compose", "up", "-d", "--wait", "redis", "bff"), True),
        ("run", ("compose", "down", "--volumes", "--remove-orphans"), False),
        "shutdown",
        "server_close",
        ("thread_join", 5),
    ]


def test_compose_derives_exact_bff_endpoints_from_one_fixture_origin() -> None:
    fallback = "${REFERENCE_BFF_FIXTURE_ORIGIN:-http://127.0.0.1:59000}"
    expected = {
        "AUTHORIZATION_ENDPOINT": f"{fallback}/oauth2/authorize",
        "TOKEN_ENDPOINT": f"{fallback}/oauth2/token",
        "COGNITO_ISSUER": f"{fallback}/test-pool",
        "COGNITO_JWKS_URL": f"{fallback}/test-pool/.well-known/jwks.json",
        "IDENTITY_API_ORIGIN": fallback,
    }
    environment = bff_environment()
    derived = {name: value for name, value in environment.items() if fallback in value}

    assert derived == expected
    assert COMPOSE_PATH.read_text(encoding="utf-8").count(fallback) == 5


def test_compose_fixes_bounded_session_refresh_coordination() -> None:
    environment = bff_environment()
    assert {
        name: environment[name]
        for name in (
            "SESSION_REFRESH_WINDOW_SECONDS",
            "REFRESH_LOCK_LEASE_SECONDS",
            "REFRESH_WAIT_TIMEOUT_MS",
            "REFRESH_POLL_INTERVAL_MS",
        )
    } == {
        "SESSION_REFRESH_WINDOW_SECONDS": '"120"',
        "REFRESH_LOCK_LEASE_SECONDS": '"10"',
        "REFRESH_WAIT_TIMEOUT_MS": '"2000"',
        "REFRESH_POLL_INTERVAL_MS": '"10"',
    }
