from __future__ import annotations

from typing import Any

import pytest

from scripts import healthcheck


def test_healthcheck_uses_canonical_origin_host_and_bounded_exact_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    class Response:
        status = 200

        def read(self, amount: int) -> bytes:
            observed["read_amount"] = amount
            return healthcheck.EXPECTED_BODY

    class Connection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            observed.update(connection_host=host, connection_port=port, timeout=timeout)

        def putrequest(self, method: str, path: str, **options: bool) -> None:
            observed.update(method=method, path=path, request_options=options)

        def putheader(self, name: str, value: str) -> None:
            observed.setdefault("headers", {})[name] = value

        def endheaders(self) -> None:
            observed["ended"] = True

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            observed["closed"] = True

    monkeypatch.setenv("IDENTITY_ORIGIN", "http://identity.test:8080")
    monkeypatch.setenv("PORT", "8080")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setattr(healthcheck.http.client, "HTTPConnection", Connection)

    assert healthcheck.check_liveness()
    assert observed["connection_host"] == "127.0.0.1"
    assert observed["connection_port"] == 8080
    assert observed["timeout"] == 2
    assert observed["headers"] == {"Host": "identity.test:8080", "Connection": "close"}
    assert observed["read_amount"] == len(healthcheck.EXPECTED_BODY) + 1
    assert observed["closed"] is True


def test_healthcheck_failure_output_is_generic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail() -> bool:
        raise RuntimeError("credential-value internal-host response-body")

    monkeypatch.setattr(healthcheck, "check_liveness", fail)
    assert healthcheck.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "health check failed\n"
