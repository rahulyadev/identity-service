"""Dependency-free process liveness probe for the packed BFF image."""

from __future__ import annotations

import http.client
import os
import sys
from urllib.parse import urlsplit

EXPECTED_BODY = b'{"status":"alive"}'


def check_liveness() -> bool:
    origin = urlsplit(os.environ.get("BFF_ORIGIN", ""))
    raw_port = os.environ.get("PORT", "8081")
    if (
        origin.scheme not in {"http", "https"}
        or not origin.hostname
        or origin.username is not None
        or origin.password is not None
        or origin.path
        or origin.query
        or origin.fragment
        or not raw_port.isascii()
        or not raw_port.isdecimal()
    ):
        return False
    port = int(raw_port)
    if not 1 <= port <= 65_535:
        return False
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.putrequest("GET", "/health/live", skip_host=True, skip_accept_encoding=True)
        host = origin.hostname if origin.port is None else f"{origin.hostname}:{origin.port}"
        connection.putheader("Host", host)
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
    except Exception:
        healthy = False
    if not healthy:
        print("health check failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
