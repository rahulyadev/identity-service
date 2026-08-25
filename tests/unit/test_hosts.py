from __future__ import annotations

import pytest

from identity_service.config.hosts import host_allowed, normalize_allowed_host, parse_host_header


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("identity.example", "identity.example"),
        ("IDENTITY.EXAMPLE", "identity.example"),
        ("identity.example:8443", "identity.example"),
        ("127.0.0.1", "127.0.0.1"),
        ("127.0.0.1:8080", "127.0.0.1"),
    ],
)
def test_strict_host_parser_accepts_exact_case_port_and_ipv4(raw: str, expected: str) -> None:
    assert parse_host_header(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " identity.example",
        "identity.example ",
        "identity example",
        "user@identity.example",
        "identity.example/path",
        "identity.example\\path",
        "identity.example?query",
        "identity.example#fragment",
        "identity.example:",
        "identity.example:0",
        "identity.example:65536",
        "identity.example:not-a-port",
        "identity.example,other.example",
        "bad..example",
        "-bad.example",
        "bad-.example",
        "999.999.999.999",
    ],
)
def test_strict_host_parser_rejects_malformed_values(raw: str) -> None:
    assert parse_host_header(raw) is None


def test_wildcard_matches_subdomains_but_not_bare_parent() -> None:
    allowed = [normalize_allowed_host("*.example.invalid")]
    assert host_allowed("api.example.invalid", allowed)
    assert host_allowed("nested.api.example.invalid", allowed)
    assert not host_allowed("example.invalid", allowed)
    assert not host_allowed("other.invalid", allowed)
