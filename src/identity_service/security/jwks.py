"""Bounded, single-flight Cognito JWKS retrieval and monotonic cache policy."""

from __future__ import annotations

import json
import math
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from identity_service.config import Settings
from identity_service.security.errors import (
    InvalidTokenError,
    JwksResponseError,
    TokenVerificationUnavailableError,
    UpstreamNetworkError,
    UpstreamResponseTooLargeError,
    UpstreamTimeoutError,
)
from identity_service.security.http import UpstreamHttpClient

JSON_MEDIA_TYPES = frozenset({"application/json", "application/jwk-set+json"})
MAX_KID_LENGTH = 128
MAX_RSA_COMPONENT_LENGTH = 2048
MAX_KEY_OPERATIONS = 8
MIN_RSA_KEY_BITS = 2048
MAX_CACHE_CONTROL_LENGTH = 4096
PRIVATE_RSA_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
CACHE_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*([0-9]{1,10})(?![0-9])", re.IGNORECASE)
CONSERVATIVE_INVALID_HEADER_FRESHNESS = 1


def _reject_nonfinite_json(_value: str) -> None:
    raise ValueError("non-finite JSON numbers are not accepted")


class JwksMetrics(Protocol):
    def record_jwks_fetch(self, outcome: str) -> None: ...

    def set_jwks_cache(self, state: str, age_seconds: float) -> None: ...


@dataclass(frozen=True, slots=True)
class JwksSnapshot:
    keys: Mapping[str, jwt.PyJWK]
    loaded_at: float
    fresh_until: float
    hard_until: float


@dataclass(frozen=True, slots=True)
class NegativeKey:
    snapshot: JwksSnapshot
    expires_at: float


class JwksCache:
    def __init__(
        self,
        settings: Settings,
        client: UpstreamHttpClient,
        *,
        metrics: JwksMetrics | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = settings.cognito_jwks_url
        self._client = client
        self._metrics = metrics
        self._clock = monotonic
        self._max_age = settings.jwks_cache_max_age_seconds
        self._stale_if_error = settings.jwks_stale_if_error_seconds
        self._refresh_min_interval = settings.jwks_refresh_min_interval_seconds
        self._negative_ttl = settings.jwks_negative_kid_cache_seconds
        self._max_keys = settings.jwks_max_keys
        self._negative_limit = min(256, max(16, self._max_keys * 4))
        self._wait_timeout = float(
            settings.upstream_connect_timeout_seconds
            + settings.upstream_read_timeout_seconds
            + settings.upstream_pool_timeout_seconds
            + 1
        )
        self._condition = threading.Condition()
        self._snapshot: JwksSnapshot | None = None
        self._refreshing = False
        self._closed = False
        self._last_failed_refresh = -math.inf
        self._last_unknown_refresh_attempt = -math.inf
        self._last_unknown_refresh_succeeded = False
        self._negative: OrderedDict[str, NegativeKey] = OrderedDict()

    @property
    def negative_cache_size(self) -> int:
        with self._condition:
            self._purge_negative(self._clock())
            return len(self._negative)

    @property
    def snapshot(self) -> JwksSnapshot | None:
        with self._condition:
            return self._snapshot

    def get_key(self, key_id: str) -> jwt.PyJWK:
        for _ in range(4):
            now = self._clock()
            with self._condition:
                if self._closed:
                    raise TokenVerificationUnavailableError("JWKS cache is closed")
                self._purge_negative(now)
                snapshot = self._snapshot
                known_key = snapshot.keys.get(key_id) if snapshot is not None else None
                negative = self._negative.get(key_id)
                if (
                    negative is not None
                    and snapshot is not None
                    and negative.snapshot is snapshot
                    and now <= negative.expires_at
                    and now <= snapshot.fresh_until
                ):
                    raise InvalidTokenError("unknown_key")
                if snapshot is not None and now <= snapshot.fresh_until and known_key is not None:
                    self._set_cache_metric("fresh", now, snapshot)
                    return known_key

                if self._refreshing:
                    if not self._condition.wait_for(
                        lambda: not self._refreshing or self._closed,
                        timeout=self._wait_timeout,
                    ):
                        raise TokenVerificationUnavailableError("JWKS refresh wait timed out")
                    continue

                failed_refresh_suppressed = (
                    now - self._last_failed_refresh < self._refresh_min_interval
                )
                if failed_refresh_suppressed:
                    if (
                        known_key is not None
                        and snapshot is not None
                        and now <= snapshot.hard_until
                    ):
                        self._set_cache_metric("degraded", now, snapshot)
                        return known_key
                    raise TokenVerificationUnavailableError("JWKS refresh retry is suppressed")

                unknown_key = known_key is None
                if (
                    unknown_key
                    and snapshot is not None
                    and now <= snapshot.fresh_until
                    and now - self._last_unknown_refresh_attempt < self._refresh_min_interval
                ):
                    if self._last_unknown_refresh_succeeded:
                        self._remember_negative(key_id, now, snapshot)
                        raise InvalidTokenError("unknown_key")
                    raise TokenVerificationUnavailableError(
                        "JWKS unknown-key refresh retry is suppressed"
                    )

                self._refreshing = True
                unknown_refresh = snapshot is not None and unknown_key

            refreshed = self._fetch_and_publish(
                key_id,
                unknown_refresh=unknown_refresh,
            )
            if refreshed:
                continue
            with self._condition:
                if self._closed:
                    raise TokenVerificationUnavailableError("JWKS cache is closed")
                snapshot = self._snapshot
                known_key = snapshot.keys.get(key_id) if snapshot is not None else None
                now = self._clock()
                if known_key is not None and snapshot is not None and now <= snapshot.hard_until:
                    self._set_cache_metric("degraded", now, snapshot)
                    return known_key
            raise TokenVerificationUnavailableError("JWKS refresh failed")

        raise TokenVerificationUnavailableError("JWKS key lookup did not converge")

    def ready(self) -> bool:
        while True:
            now = self._clock()
            with self._condition:
                if self._closed:
                    self._set_cache_metric("unavailable", now, self._snapshot)
                    return False
                snapshot = self._snapshot
                if snapshot is not None and now <= snapshot.fresh_until:
                    self._set_cache_metric("fresh", now, snapshot)
                    return True
                if self._refreshing:
                    if not self._condition.wait_for(
                        lambda: not self._refreshing or self._closed,
                        timeout=self._wait_timeout,
                    ):
                        self._set_cache_metric("unavailable", self._clock(), self._snapshot)
                        return False
                    continue
                if now - self._last_failed_refresh < self._refresh_min_interval:
                    ready = snapshot is not None and now <= snapshot.hard_until
                    self._set_cache_metric("degraded" if ready else "unavailable", now, snapshot)
                    return ready
                self._refreshing = True

            refreshed = self._fetch_and_publish(None, unknown_refresh=False)
            now = self._clock()
            with self._condition:
                snapshot = self._snapshot
                if self._is_closed():
                    self._set_cache_metric("unavailable", now, snapshot)
                    return False
                ready = refreshed or (snapshot is not None and now <= snapshot.hard_until)
                state = "fresh" if refreshed else ("degraded" if ready else "unavailable")
                self._set_cache_metric(state, now, snapshot)
                return ready

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    def _is_closed(self) -> bool:
        return self._closed

    def _fetch_and_publish(
        self,
        requested_key_id: str | None,
        *,
        unknown_refresh: bool,
    ) -> bool:
        snapshot: JwksSnapshot | None = None
        recognized_error: (
            JwksResponseError
            | UpstreamNetworkError
            | UpstreamResponseTooLargeError
            | UpstreamTimeoutError
            | None
        ) = None
        published = False
        try:
            snapshot = self._fetch_snapshot()
        except (
            JwksResponseError,
            UpstreamNetworkError,
            UpstreamResponseTooLargeError,
            UpstreamTimeoutError,
        ) as error:
            recognized_error = error
        finally:
            completed_at = self._clock()
            with self._condition:
                if recognized_error is not None:
                    self._last_failed_refresh = completed_at
                    if unknown_refresh:
                        self._last_unknown_refresh_attempt = completed_at
                        self._last_unknown_refresh_succeeded = False
                elif snapshot is not None and not self._closed:
                    self._snapshot = snapshot
                    self._negative.clear()
                    self._last_failed_refresh = -math.inf
                    published = True
                    if unknown_refresh:
                        self._last_unknown_refresh_attempt = completed_at
                        self._last_unknown_refresh_succeeded = True
                    if requested_key_id is not None and requested_key_id not in snapshot.keys:
                        self._remember_negative(requested_key_id, completed_at, snapshot)
                elif snapshot is None and unknown_refresh:
                    # An unexpected exception is re-raised after finalization and may be
                    # retried immediately once the programming defect or test fault clears.
                    self._last_unknown_refresh_attempt = -math.inf
                    self._last_unknown_refresh_succeeded = False
                self._refreshing = False
                self._condition.notify_all()

        if recognized_error is not None:
            if self._metrics is not None:
                if isinstance(recognized_error, UpstreamTimeoutError):
                    outcome = "timeout"
                elif isinstance(recognized_error, UpstreamNetworkError):
                    outcome = "network_error"
                elif isinstance(recognized_error, UpstreamResponseTooLargeError):
                    outcome = "oversized"
                else:
                    outcome = "malformed"
                self._metrics.record_jwks_fetch(outcome)
            return False
        if published and self._metrics is not None:
            self._metrics.record_jwks_fetch("success")
        return published

    def _fetch_snapshot(self) -> JwksSnapshot:
        response = self._client.get(
            self._url,
            headers={"Accept": "application/jwk-set+json, application/json"},
        )
        if response.status_code != 200:
            raise JwksResponseError("JWKS endpoint did not return success")
        content_type = response.headers.get("content-type", "").partition(";")[0].strip().casefold()
        if content_type not in JSON_MEDIA_TYPES:
            raise JwksResponseError("JWKS endpoint returned an unsupported media type")
        try:
            document = json.loads(response.body, parse_constant=_reject_nonfinite_json)
        except UnicodeDecodeError, RecursionError, ValueError:
            raise JwksResponseError("JWKS endpoint returned malformed JSON") from None
        if not isinstance(document, dict) or "keys" not in document:
            raise JwksResponseError("JWKS response must contain a keys array")
        raw_keys = document["keys"]
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= self._max_keys:
            raise JwksResponseError("JWKS keys array has an unsafe size")

        parsed_keys: dict[str, jwt.PyJWK] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise JwksResponseError("JWKS key is not an object")
            key_id = raw_key.get("kid")
            if (
                not isinstance(key_id, str)
                or not 1 <= len(key_id) <= MAX_KID_LENGTH
                or any(ord(character) < 33 or ord(character) == 127 for character in key_id)
                or key_id in parsed_keys
            ):
                raise JwksResponseError("JWKS key identifier is invalid or duplicated")
            if (
                raw_key.get("kty") != "RSA"
                or raw_key.get("use") != "sig"
                or raw_key.get("alg", "RS256") != "RS256"
            ):
                raise JwksResponseError("JWKS key is not an RS256 signing key")
            key_operations = raw_key.get("key_ops")
            if key_operations is not None and (
                not isinstance(key_operations, list)
                or not 1 <= len(key_operations) <= MAX_KEY_OPERATIONS
                or any(
                    not isinstance(operation, str) or not 1 <= len(operation) <= 32
                    for operation in key_operations
                )
                or len(set(key_operations)) != len(key_operations)
                or set(key_operations) != {"verify"}
            ):
                raise JwksResponseError("JWKS key operations are incompatible with verification")
            if PRIVATE_RSA_FIELDS.intersection(raw_key):
                raise JwksResponseError("JWKS response contains private RSA material")
            modulus = raw_key.get("n")
            exponent = raw_key.get("e")
            if (
                not isinstance(modulus, str)
                or not 1 <= len(modulus) <= MAX_RSA_COMPONENT_LENGTH
                or not isinstance(exponent, str)
                or not 1 <= len(exponent) <= 16
            ):
                raise JwksResponseError("JWKS RSA material is invalid")
            try:
                parsed = jwt.PyJWK.from_dict(raw_key, algorithm="RS256")
            except jwt.PyJWKError, ValueError, TypeError:
                raise JwksResponseError("JWKS RSA key cannot be parsed") from None
            if parsed.key_type != "RSA" or parsed.algorithm_name != "RS256":
                raise JwksResponseError("JWKS parsed key violates the algorithm policy")
            if (
                not isinstance(parsed.key, rsa.RSAPublicKey)
                or parsed.key.key_size < MIN_RSA_KEY_BITS
            ):
                raise JwksResponseError("JWKS RSA key does not meet the strength policy")
            parsed_keys[key_id] = parsed

        now = self._clock()
        advertised = self._upstream_max_age(response.headers.get("cache-control", ""))
        fresh_for = min(self._max_age, advertised) if advertised is not None else self._max_age
        return JwksSnapshot(
            keys=MappingProxyType(parsed_keys),
            loaded_at=now,
            fresh_until=now + fresh_for,
            hard_until=now + self._stale_if_error,
        )

    @staticmethod
    def _upstream_max_age(value: str) -> int | None:
        if len(value) > MAX_CACHE_CONTROL_LENGTH:
            return CONSERVATIVE_INVALID_HEADER_FRESHNESS
        matches = [int(match) for match in CACHE_MAX_AGE.findall(value)]
        return min(matches) if matches else None

    def _purge_negative(self, now: float) -> None:
        snapshot = self._snapshot
        expired = [
            key
            for key, negative in self._negative.items()
            if negative.snapshot is not snapshot
            or now > negative.expires_at
            or snapshot is None
            or now > snapshot.fresh_until
        ]
        for key in expired:
            self._negative.pop(key, None)

    def _remember_negative(self, key_id: str, now: float, snapshot: JwksSnapshot) -> None:
        self._negative[key_id] = NegativeKey(
            snapshot=snapshot,
            expires_at=min(now + self._negative_ttl, snapshot.fresh_until),
        )
        self._negative.move_to_end(key_id)
        while len(self._negative) > self._negative_limit:
            self._negative.popitem(last=False)

    def _set_cache_metric(self, state: str, now: float, snapshot: JwksSnapshot | None) -> None:
        if self._metrics is not None:
            age = max(0.0, now - snapshot.loaded_at) if snapshot is not None else 0.0
            self._metrics.set_jwks_cache(state, age)
