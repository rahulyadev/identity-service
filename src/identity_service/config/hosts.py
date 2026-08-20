"""Strict configured-host and HTTP Host-header handling."""

from __future__ import annotations

import ipaddress
import re

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_HOST_FORBIDDEN = frozenset("/@\\?#[]")


def _normalize_dns_or_ipv4(value: str) -> str | None:
    host = value.lower()
    if not host or len(host) > 253 or any(character in _HOST_FORBIDDEN for character in host):
        return None
    if any(character.isspace() or ord(character) > 127 for character in host):
        return None

    if re.fullmatch(r"[0-9.]+", host):
        try:
            return str(ipaddress.IPv4Address(host))
        except ipaddress.AddressValueError:
            return None

    labels = host.split(".")
    if any(not _DNS_LABEL.fullmatch(label) for label in labels):
        return None
    return host


def normalize_allowed_host(value: str) -> str:
    """Validate and normalize one exact or wildcard configured host."""

    if value != value.strip() or not value or value == "*":
        raise ValueError("hosts must be explicit and contain no surrounding whitespace")
    wildcard = value.startswith("*.")
    candidate = value[2:] if wildcard else value
    normalized = _normalize_dns_or_ipv4(candidate)
    if normalized is None or (wildcard and re.fullmatch(r"[0-9.]+", candidate)):
        raise ValueError("each host must be a DNS name or IPv4 address without a port")
    return f"*.{normalized}" if wildcard else normalized


def parse_host_header(value: str) -> str | None:
    """Return a normalized hostname only for the supported strict Host grammar."""

    if value != value.strip() or not value or any(character.isspace() for character in value):
        return None
    if any(character in _HOST_FORBIDDEN for character in value) or value.count(":") > 1:
        return None

    raw_host = value
    if ":" in value:
        raw_host, raw_port = value.rsplit(":", maxsplit=1)
        if not raw_port or not raw_port.isascii() or not raw_port.isdecimal():
            return None
        port = int(raw_port)
        if not 1 <= port <= 65535:
            return None

    return _normalize_dns_or_ipv4(raw_host)


def host_allowed(host: str | None, allowed_hosts: list[str]) -> bool:
    """Match an exact host or a wildcard subdomain, never the wildcard parent."""

    if host is None:
        return False
    normalized = host.lower()
    return any(
        normalized == allowed
        or (
            allowed.startswith("*.")
            and normalized.endswith(allowed[1:])
            and normalized != allowed[2:]
        )
        for allowed in allowed_hosts
    )
