"""HTTP adapter for the in-memory Cognito test fixture used by packed smoke tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx2

from tests.fixtures.fake_cognito import FakeCognito


class FakeCognitoServer:
    """Expose ``FakeCognito`` to a local packed container without provider traffic."""

    def __init__(self, fixture: FakeCognito) -> None:
        fixture_reference = fixture

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                request = httpx2.Request(
                    "GET",
                    f"http://cognito.test{self.path}",
                    headers=dict(self.headers.items()),
                )
                response = fixture_reference.handle(request)
                self.send_response(response.status_code)
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(response.content)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        # Docker bridge clients need a host-interface bind; this server exists only in tests.
        self._server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)  # nosec B104
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="fake-cognito-http",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
