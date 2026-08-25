"""Bounded, proxy-independent liveness probe for the packed container."""

from __future__ import annotations

import http.client
import os
import sys
from urllib.parse import urlsplit

EXPECTED_BODY = b'{"status":"alive"}'


def canonical_host_header(origin: str) -> str:
    """Derive the HTTP Host value from a validated canonical origin."""

    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "\\" in origin
        or "?" in origin
        or "#" in origin
    ):
        raise ValueError("invalid canonical origin")
    port = parsed.port
    return parsed.hostname if port is None else f"{parsed.hostname}:{port}"


def check_liveness() -> bool:
    origin = os.environ.get("IDENTITY_ORIGIN", "")
    raw_port = os.environ.get("PORT", "8080")
    if not raw_port.isascii() or not raw_port.isdecimal():
        return False
    port = int(raw_port)
    if not 1 <= port <= 65535:
        return False

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.putrequest("GET", "/health/live", skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", canonical_host_header(origin))
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        body = response.read(len(EXPECTED_BODY) + 1)
        return response.status == 200 and body == EXPECTED_BODY
    finally:
        connection.close()


def main() -> int:
    try:
        healthy = check_liveness()
    except Exception:  # The health-check interface intentionally exposes no internal detail.
        healthy = False
    if not healthy:
        print("health check failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
