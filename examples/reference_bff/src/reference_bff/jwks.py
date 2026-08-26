"""Bounded async single-flight JWKS retrieval for the reference BFF."""

from __future__ import annotations

import asyncio
import math
import re
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from reference_bff.config import Settings
from reference_bff.http import (
    AsyncUpstreamClient,
    UpstreamError,
    json_media_type,
)
from reference_bff.json_safety import UnsafeJsonError, load_json_object

JSON_MEDIA_TYPES = frozenset({"application/json", "application/jwk-set+json"})
PRIVATE_RSA_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
CACHE_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*([0-9]{1,10})(?![0-9])", re.I)
KID = re.compile(r"[\x21-\x7e]{1,128}")
MIN_RSA_KEY_BITS = 2048
MAX_RSA_COMPONENT_LENGTH = 2048
MAX_KEY_OPERATIONS = 8
MAX_CACHE_CONTROL_LENGTH = 4096


class InvalidSigningKeyError(ValueError):
    """The token named a key absent from a successfully refreshed JWKS."""


class JwksUnavailableError(RuntimeError):
    """No safe signing key or usable bounded snapshot is currently available."""


class JwksResponseError(RuntimeError):
    """The JWKS endpoint returned an unsafe or invalid response."""


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


class AsyncJwksCache:
    def __init__(
        self,
        settings: Settings,
        client: AsyncUpstreamClient,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = settings.cognito_jwks_url
        self._client = client
        self._clock = monotonic
        self._max_age = settings.jwks_cache_max_age_seconds
        self._stale_if_error = settings.jwks_stale_if_error_seconds
        self._refresh_min_interval = settings.jwks_refresh_min_interval_seconds
        self._negative_ttl = settings.jwks_negative_kid_cache_seconds
        self._max_keys = settings.jwks_max_keys
        self._negative_limit = min(256, max(16, self._max_keys * 4))
        self._lock = asyncio.Lock()
        self._snapshot: JwksSnapshot | None = None
        self._closed = False
        self._last_failed_refresh = -math.inf
        self._last_unknown_refresh = -math.inf
        self._last_unknown_refresh_succeeded = False
        self._negative: OrderedDict[str, NegativeKey] = OrderedDict()

    @property
    def snapshot(self) -> JwksSnapshot | None:
        return self._snapshot

    async def get_key(self, key_id: str) -> jwt.PyJWK:
        if KID.fullmatch(key_id) is None:
            raise InvalidSigningKeyError("invalid signing key identifier")
        now = self._clock()
        key = self._fresh_key_or_negative(key_id, now)
        if key is not None:
            return key
        async with self._lock:
            if self._closed:
                raise JwksUnavailableError("JWKS cache is closed")
            now = self._clock()
            key = self._fresh_key_or_negative(key_id, now)
            if key is not None:
                return key
            snapshot = self._snapshot
            known = snapshot.keys.get(key_id) if snapshot is not None else None
            if now - self._last_failed_refresh < self._refresh_min_interval:
                if known is not None and snapshot is not None and now <= snapshot.hard_until:
                    return known
                raise JwksUnavailableError("JWKS refresh retry is suppressed")
            unknown_refresh = snapshot is not None and known is None
            if unknown_refresh and now - self._last_unknown_refresh < self._refresh_min_interval:
                if self._last_unknown_refresh_succeeded and snapshot is not None:
                    self._remember_negative(key_id, now, snapshot)
                    raise InvalidSigningKeyError("unknown signing key")
                raise JwksUnavailableError("unknown-key refresh retry is suppressed")
            if unknown_refresh:
                self._last_unknown_refresh = now
            try:
                refreshed = await self._fetch_snapshot()
            except JwksResponseError, UpstreamError:
                self._last_failed_refresh = self._clock()
                if unknown_refresh:
                    self._last_unknown_refresh_succeeded = False
                if known is not None and snapshot is not None and now <= snapshot.hard_until:
                    return known
                raise JwksUnavailableError("JWKS refresh failed") from None
            self._snapshot = refreshed
            self._negative.clear()
            self._last_failed_refresh = -math.inf
            if unknown_refresh:
                self._last_unknown_refresh_succeeded = True
            key = refreshed.keys.get(key_id)
            if key is None:
                self._remember_negative(key_id, self._clock(), refreshed)
                raise InvalidSigningKeyError("unknown signing key")
            return key

    async def ready(self) -> bool:
        if self._closed:
            return False
        now = self._clock()
        snapshot = self._snapshot
        if snapshot is not None and now <= snapshot.fresh_until and bool(snapshot.keys):
            return True
        async with self._lock:
            now = self._clock()
            snapshot = self._snapshot
            if snapshot is not None and now <= snapshot.fresh_until and bool(snapshot.keys):
                return True
            if now - self._last_failed_refresh < self._refresh_min_interval:
                return bool(snapshot and snapshot.keys and now <= snapshot.hard_until)
            try:
                refreshed = await self._fetch_snapshot()
            except JwksResponseError, UpstreamError:
                self._last_failed_refresh = self._clock()
                return bool(snapshot and snapshot.keys and now <= snapshot.hard_until)
            self._snapshot = refreshed
            self._negative.clear()
            self._last_failed_refresh = -math.inf
            return bool(refreshed.keys)

    def close(self) -> None:
        self._closed = True
        self._snapshot = None
        self._negative.clear()

    def _fresh_key_or_negative(self, key_id: str, now: float) -> jwt.PyJWK | None:
        if self._closed:
            raise JwksUnavailableError("JWKS cache is closed")
        self._purge_negative(now)
        snapshot = self._snapshot
        if snapshot is None:
            return None
        negative = self._negative.get(key_id)
        if negative is not None and negative.snapshot is snapshot and now <= negative.expires_at:
            raise InvalidSigningKeyError("unknown signing key")
        key = snapshot.keys.get(key_id)
        return key if key is not None and now <= snapshot.fresh_until else None

    async def _fetch_snapshot(self) -> JwksSnapshot:
        response = await self._client.request(
            "GET", self._url, headers={"Accept": "application/json"}
        )
        if response.status_code != 200:
            raise JwksResponseError("JWKS endpoint did not return success")
        if not json_media_type(response.headers, allowed=JSON_MEDIA_TYPES):
            raise JwksResponseError("JWKS endpoint returned an unsupported media type")
        try:
            document = load_json_object(response.body)
        except UnsafeJsonError:
            raise JwksResponseError("JWKS endpoint returned malformed JSON") from None
        if set(document) != {"keys"} or type(document["keys"]) is not list:
            raise JwksResponseError("JWKS response must contain only a keys array")
        raw_keys = document["keys"]
        if not 1 <= len(raw_keys) <= self._max_keys:
            raise JwksResponseError("JWKS keys array has an unsafe size")
        keys: dict[str, jwt.PyJWK] = {}
        for raw_key in raw_keys:
            if type(raw_key) is not dict:
                raise JwksResponseError("JWKS key is not an object")
            key_id = raw_key.get("kid")
            if type(key_id) is not str or KID.fullmatch(key_id) is None or key_id in keys:
                raise JwksResponseError("JWKS key identifier is invalid or duplicated")
            if (
                raw_key.get("kty") != "RSA"
                or raw_key.get("use") != "sig"
                or raw_key.get("alg", "RS256") != "RS256"
            ):
                raise JwksResponseError("JWKS key is not an RS256 signing key")
            operations = raw_key.get("key_ops")
            if operations is not None and (
                type(operations) is not list
                or not 1 <= len(operations) <= MAX_KEY_OPERATIONS
                or any(
                    type(operation) is not str or not 1 <= len(operation) <= 32
                    for operation in operations
                )
                or len(set(operations)) != len(operations)
                or set(operations) != {"verify"}
            ):
                raise JwksResponseError("JWKS key operations are incompatible")
            if PRIVATE_RSA_FIELDS.intersection(raw_key):
                raise JwksResponseError("JWKS response contains private key material")
            modulus = raw_key.get("n")
            exponent = raw_key.get("e")
            if (
                type(modulus) is not str
                or not 1 <= len(modulus) <= MAX_RSA_COMPONENT_LENGTH
                or type(exponent) is not str
                or not 1 <= len(exponent) <= 16
            ):
                raise JwksResponseError("JWKS RSA material is invalid")
            try:
                parsed = jwt.PyJWK.from_dict(raw_key, algorithm="RS256")
            except jwt.PyJWKError, TypeError, ValueError:
                raise JwksResponseError("JWKS RSA key cannot be parsed") from None
            if (
                parsed.key_type != "RSA"
                or parsed.algorithm_name != "RS256"
                or not isinstance(parsed.key, rsa.RSAPublicKey)
                or parsed.key.key_size < MIN_RSA_KEY_BITS
            ):
                raise JwksResponseError("JWKS RSA key violates the strength policy")
            keys[key_id] = parsed
        now = self._clock()
        advertised = self._upstream_max_age(response.headers.get("cache-control", ""))
        fresh_for = min(self._max_age, advertised) if advertised is not None else self._max_age
        return JwksSnapshot(
            keys=MappingProxyType(keys),
            loaded_at=now,
            fresh_until=now + fresh_for,
            hard_until=now + self._stale_if_error,
        )

    @staticmethod
    def _upstream_max_age(value: str) -> int | None:
        if len(value) > MAX_CACHE_CONTROL_LENGTH:
            return 1
        values = [int(match) for match in CACHE_MAX_AGE.findall(value)]
        return min(values) if values else None

    def _purge_negative(self, now: float) -> None:
        snapshot = self._snapshot
        for key, value in tuple(self._negative.items()):
            if value.snapshot is not snapshot or now > value.expires_at:
                self._negative.pop(key, None)

    def _remember_negative(self, key_id: str, now: float, snapshot: JwksSnapshot) -> None:
        self._negative[key_id] = NegativeKey(
            snapshot=snapshot,
            expires_at=min(now + self._negative_ttl, snapshot.fresh_until),
        )
        self._negative.move_to_end(key_id)
        while len(self._negative) > self._negative_limit:
            self._negative.popitem(last=False)
