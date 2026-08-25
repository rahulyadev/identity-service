from __future__ import annotations

import threading
import time
import warnings
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx2
import pytest

from identity_service.config import Settings
from identity_service.security import AccessTokenVerifier, JwksCache, UpstreamHttpClient
from identity_service.security.errors import InvalidTokenError, TokenVerificationUnavailableError
from tests.fixtures.fake_cognito import FakeCognito


class MonotonicClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class RecordingJwksMetrics:
    def __init__(self) -> None:
        self.fetch_outcomes: list[str] = []
        self.cache_states: list[str] = []

    def record_jwks_fetch(self, outcome: str) -> None:
        self.fetch_outcomes.append(outcome)

    def set_jwks_cache(self, state: str, age_seconds: float) -> None:
        assert age_seconds >= 0
        self.cache_states.append(state)


class ExplodingFetchMetrics(RecordingJwksMetrics):
    def record_jwks_fetch(self, outcome: str) -> None:
        super().record_jwks_fetch(outcome)
        raise RuntimeError("synthetic metrics failure")


def _components(
    settings_factory: Callable[..., Settings],
    fake: FakeCognito,
    *,
    clock: Callable[[], float] | None = None,
    transport: httpx2.BaseTransport | None = None,
    metrics: RecordingJwksMetrics | None = None,
    **overrides: object,
) -> tuple[UpstreamHttpClient, JwksCache, AccessTokenVerifier]:
    values = fake.settings_overrides()
    values.update(
        {
            "jwks_cache_max_age_seconds": 10,
            "jwks_stale_if_error_seconds": 30,
            "jwks_refresh_min_interval_seconds": 5,
            "jwks_negative_kid_cache_seconds": 2,
        }
    )
    values.update(overrides)
    settings = settings_factory(**values)
    client = UpstreamHttpClient(settings, transport=transport or fake.transport())
    cache = JwksCache(
        settings,
        client,
        monotonic=clock or time.monotonic,
        metrics=metrics,
    )
    return client, cache, AccessTokenVerifier(settings, cache)


def test_first_load_and_fresh_hit_fetch_once(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    client, cache, verifier = _components(settings_factory, fake_cognito)
    try:
        first = verifier.verify_access_token(fake_cognito.token())
        second = verifier.verify_access_token(fake_cognito.token())
    finally:
        cache.close()
        client.close()
    assert first.subject == second.subject
    assert fake_cognito.jwks_fetches == 1


@pytest.mark.parametrize(
    ("cache_control", "expected_fresh_for"),
    [
        ("public, max-age=2", 2),
        ("max-age=9999", 10),
        ("no-cache", 10),
        ("max-age=8, max-age=3", 3),
    ],
)
def test_upstream_cache_control_can_lower_but_not_raise_cap(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    cache_control: str,
    expected_fresh_for: int,
) -> None:
    clock = MonotonicClock()
    fake_cognito.cache_control = cache_control
    client, cache, _ = _components(settings_factory, fake_cognito, clock=clock)
    try:
        assert cache.ready()
        snapshot = cache.snapshot
    finally:
        cache.close()
        client.close()
    assert snapshot is not None
    assert snapshot.fresh_until - snapshot.loaded_at == expected_fresh_for


@pytest.mark.parametrize(
    ("cache_control", "expected_fresh_for"),
    [
        ("max-age=" + "9" * 5000, 1),
        ("max-age=" + "9" * 100, 10),
        ("max-age=invalid, max-age=8, max-age=3", 3),
    ],
)
def test_cache_control_numeric_parsing_is_bounded_and_conservative(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    cache_control: str,
    expected_fresh_for: int,
) -> None:
    clock = MonotonicClock()
    fake_cognito.cache_control = cache_control
    client, cache, _ = _components(settings_factory, fake_cognito, clock=clock)
    try:
        assert cache.ready()
        snapshot = cache.snapshot
    finally:
        cache.close()
        client.close()
    assert snapshot is not None
    assert snapshot.fresh_until - snapshot.loaded_at == expected_fresh_for


def test_lower_upstream_max_age_forces_one_post_expiry_single_flight_refresh(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    fake_cognito.cache_control = "public, max-age=2"
    entered = threading.Event()
    release = threading.Event()
    block_refresh = False

    def handler(request: httpx2.Request) -> httpx2.Response:
        if block_refresh:
            entered.set()
            assert release.wait(timeout=2)
        return fake_cognito.handle(request)

    metrics = RecordingJwksMetrics()
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        transport=httpx2.MockTransport(handler),
        metrics=metrics,
        jwks_refresh_min_interval_seconds=10,
    )
    key_id = fake_cognito.active_kid
    try:
        assert cache.ready()
        assert fake_cognito.jwks_fetches == 1
        clock.advance(1)
        assert cache.get_key(key_id)
        assert fake_cognito.jwks_fetches == 1

        clock.advance(2)
        block_refresh = True
        barrier = threading.Barrier(20)

        def lookup() -> str:
            barrier.wait()
            return cache.get_key(key_id).key_id

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(lookup) for _ in range(20)]
            assert entered.wait(timeout=1)
            release.set()
            assert [future.result(timeout=2) for future in futures] == [key_id] * 20
        assert fake_cognito.jwks_fetches == 2
        assert cache.snapshot is not None
        assert cache.snapshot.loaded_at == 3
    finally:
        release.set()
        cache.close()
        client.close()
    assert "degraded" not in metrics.cache_states


def test_failed_refresh_retry_suppression_unknown_key_and_hard_stale_policy(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    fake_cognito.cache_control = "max-age=2"
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        jwks_refresh_min_interval_seconds=10,
        jwks_stale_if_error_seconds=30,
    )
    key_id = fake_cognito.active_kid
    try:
        assert cache.ready()
        fake_cognito.jwks_status = 500
        clock.advance(3)
        assert cache.get_key(key_id)
        assert fake_cognito.jwks_fetches == 2
        assert cache.get_key(key_id)
        with pytest.raises(TokenVerificationUnavailableError):
            cache.get_key("possible-rotation")
        assert fake_cognito.jwks_fetches == 2

        clock.advance(10)
        assert cache.get_key(key_id)
        assert fake_cognito.jwks_fetches == 3

        clock.advance(18)
        with pytest.raises(TokenVerificationUnavailableError):
            cache.get_key(key_id)
        assert fake_cognito.jwks_fetches == 4

        fake_cognito.jwks_status = 200
        clock.advance(10)
        assert cache.get_key(key_id)
        assert fake_cognito.jwks_fetches == 5
        assert cache.snapshot is not None
        assert cache.snapshot.loaded_at == 41
    finally:
        cache.close()
        client.close()


def test_successful_unknown_key_refresh_creates_only_exact_bounded_negative_result(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        jwks_refresh_min_interval_seconds=5,
    )
    try:
        assert cache.ready()
        with pytest.raises(InvalidTokenError):
            cache.get_key("confirmed-absent")
        assert fake_cognito.jwks_fetches == 2
        fake_cognito.jwks_status = 500
        with pytest.raises(InvalidTokenError):
            cache.get_key("confirmed-absent")
        assert fake_cognito.jwks_fetches == 2

        clock.advance(5)
        with pytest.raises(TokenVerificationUnavailableError):
            cache.get_key("possible-rotation")
        assert fake_cognito.jwks_fetches == 3
        with pytest.raises(TokenVerificationUnavailableError):
            cache.get_key("another-possible-rotation")
        assert fake_cognito.jwks_fetches == 3
    finally:
        cache.close()
        client.close()


def test_negative_key_result_expires_with_proving_snapshot_and_accepts_rotation(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    fake_cognito.cache_control = "max-age=2"
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        jwks_negative_kid_cache_seconds=10,
    )
    rotated = "rotated-kid"
    try:
        assert cache.ready()
        with pytest.raises(InvalidTokenError, match="invalid"):
            cache.get_key(rotated)
        assert fake_cognito.jwks_fetches == 2
        with pytest.raises(InvalidTokenError, match="invalid"):
            cache.get_key(rotated)
        assert fake_cognito.jwks_fetches == 2

        fake_cognito.rotate(rotated)
        clock.advance(3)
        fake_cognito.jwks_delay_seconds = 0.05
        barrier = threading.Barrier(20)

        def lookup() -> str:
            barrier.wait()
            return cache.get_key(rotated).key_id

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(lambda _: lookup(), range(20)))
        assert results == [rotated] * 20
        assert fake_cognito.jwks_fetches == 3
    finally:
        cache.close()
        client.close()


def test_successful_expiry_refresh_proves_removed_key_absent_without_second_fetch(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    fake_cognito.cache_control = "max-age=2"
    old_key = fake_cognito.active_kid
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise AssertionError("a successful absence refresh must be authoritative")
        return fake_cognito.handle(request)

    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        transport=httpx2.MockTransport(handler),
    )
    try:
        assert cache.get_key(old_key).key_id == old_key
        new_key = fake_cognito.rotate("replacement-key", retain_old=False)
        clock.advance(3)
        with pytest.raises(InvalidTokenError) as captured:
            cache.get_key(old_key)
        assert captured.value.outcome == "unknown_key"
        assert calls == 2
        assert cache.get_key(new_key).key_id == new_key
        assert calls == 2
    finally:
        cache.close()
        client.close()


def test_failed_expiry_refresh_preserves_known_key_only_through_hard_stale_bound(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    fake_cognito.cache_control = "max-age=2"
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        jwks_stale_if_error_seconds=8,
        jwks_refresh_min_interval_seconds=3,
        jwks_cache_max_age_seconds=2,
    )
    old_key = fake_cognito.active_kid
    try:
        assert cache.get_key(old_key).key_id == old_key
        fake_cognito.jwks_status = 500
        clock.advance(3)
        assert cache.get_key(old_key).key_id == old_key
        clock.advance(6)
        with pytest.raises(TokenVerificationUnavailableError):
            cache.get_key(old_key)
    finally:
        cache.close()
        client.close()


def test_unknown_key_forces_one_rotation_refresh(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    client, cache, verifier = _components(settings_factory, fake_cognito)
    try:
        verifier.verify_access_token(fake_cognito.token())
        new_kid = fake_cognito.rotate()
        verified = verifier.verify_access_token(fake_cognito.token(key_id=new_kid))
    finally:
        cache.close()
        client.close()
    assert verified.subject == "opaque-Subject_1"
    assert fake_cognito.jwks_fetches == 2


def test_successful_refresh_without_unknown_key_is_invalid_token(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    client, cache, verifier = _components(settings_factory, fake_cognito)
    try:
        verifier.verify_access_token(fake_cognito.token())
        with pytest.raises(InvalidTokenError) as captured:
            verifier.verify_access_token(fake_cognito.token(key_id="absent"))
    finally:
        cache.close()
        client.close()
    assert captured.value.outcome == "unknown_key"
    assert fake_cognito.jwks_fetches == 2


def test_unknown_key_plus_outage_is_dependency_unavailable(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    client, cache, verifier = _components(settings_factory, fake_cognito)
    try:
        verifier.verify_access_token(fake_cognito.token())
        fake_cognito.jwks_status = 500
        with pytest.raises(TokenVerificationUnavailableError):
            verifier.verify_access_token(fake_cognito.token(key_id="possibly-rotated"))
    finally:
        cache.close()
        client.close()


def test_known_key_uses_bounded_stale_cache_but_not_hard_stale_cache(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    client, cache, verifier = _components(settings_factory, fake_cognito, clock=clock)
    token = fake_cognito.token()
    try:
        verifier.verify_access_token(token)
        fake_cognito.jwks_status = 500
        clock.advance(11)
        assert verifier.verify_access_token(token).subject == "opaque-Subject_1"
        clock.advance(20)
        with pytest.raises(TokenVerificationUnavailableError):
            verifier.verify_access_token(token)
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize(
    "mode",
    [
        "malformed_json",
        "empty",
        "duplicate",
        "wrong_type",
        "wrong_use",
        "wrong_alg",
        "malformed_key",
        "key_ops_encrypt",
        "key_ops_sign",
        "key_ops_duplicate",
        "key_ops_wrong_type",
        "private_key_material",
        "too_many",
        "missing_keys",
        "keys_wrong_type",
    ],
)
def test_invalid_refresh_never_replaces_prior_snapshot(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito, mode: str
) -> None:
    clock = MonotonicClock()
    client, cache, verifier = _components(settings_factory, fake_cognito, clock=clock)
    token = fake_cognito.token()
    try:
        verifier.verify_access_token(token)
        original = cache.snapshot
        fake_cognito.jwks_mode = mode
        clock.advance(11)
        assert verifier.verify_access_token(token).subject == "opaque-Subject_1"
        assert cache.snapshot is original
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize(
    ("mode", "constant"),
    [
        ("integer_limit", "NaN"),
        ("nonfinite", "NaN"),
        ("nonfinite", "Infinity"),
        ("nonfinite", "-Infinity"),
    ],
)
def test_untrusted_jwks_numeric_json_is_typed_preserves_snapshot_and_recovers(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    mode: str,
    constant: str,
) -> None:
    clock = MonotonicClock()
    metrics = RecordingJwksMetrics()
    client, cache, _ = _components(settings_factory, fake_cognito, clock=clock, metrics=metrics)
    try:
        assert cache.ready()
        original = cache.snapshot
        fake_cognito.nonfinite_constant = constant
        fake_cognito.jwks_mode = mode
        clock.advance(11)
        assert cache.ready()
        assert cache.snapshot is original
        assert metrics.fetch_outcomes[-1] == "malformed"
        fake_cognito.jwks_mode = "valid"
        clock.advance(5)
        assert cache.ready()
        assert cache.snapshot is not original
    finally:
        cache.close()
        client.close()


def test_jwk_set_additional_members_are_ignored_without_policy_influence(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    fake_cognito.jwks_extra_members = {
        "metadata": "ignored",
        "jwks_uri": "https://alternate.invalid/keys",
        "alg": "none",
        "cache_max_age": 999999,
    }
    client, cache, verifier = _components(settings_factory, fake_cognito)
    try:
        assert cache.ready()
        assert verifier.verify_access_token(fake_cognito.token()).subject == "opaque-Subject_1"
        snapshot = cache.snapshot
    finally:
        cache.close()
        client.close()
    assert fake_cognito.jwks_fetches == 1
    assert snapshot is not None
    assert set(snapshot.keys) == {fake_cognito.active_kid}
    assert snapshot.fresh_until - snapshot.loaded_at == 10


@pytest.mark.parametrize("key_size", [1024, 2048, 3072])
def test_jwks_enforces_actual_rsa_public_key_strength(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    key_size: int,
) -> None:
    fake_cognito.rotate("sized-key", retain_old=False, key_size=key_size)
    metrics = RecordingJwksMetrics()
    client, cache, _ = _components(settings_factory, fake_cognito, metrics=metrics)
    try:
        with warnings.catch_warnings(record=True) as caught:
            ready = cache.ready()
        snapshot = cache.snapshot
    finally:
        cache.close()
        client.close()
    assert ready is (key_size >= 2048)
    assert (snapshot is not None) is (key_size >= 2048)
    assert not [warning for warning in caught if "key" in str(warning.message).casefold()]
    assert metrics.fetch_outcomes == ["success" if key_size >= 2048 else "malformed"]


def test_weak_refresh_rejects_entire_mixed_snapshot_and_preserves_valid_snapshot(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    client, cache, _ = _components(settings_factory, fake_cognito, clock=clock)
    try:
        assert cache.ready()
        original = cache.snapshot
        fake_cognito.rotate("weak-key", key_size=1024)
        clock.advance(11)
        assert cache.ready()
        assert cache.snapshot is original
        assert "weak-key" not in cache.snapshot.keys
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize(
    ("mode", "status", "content_type", "response_limit"),
    [
        ("empty", 200, "application/jwk-set+json", 65_536),
        ("duplicate", 200, "application/jwk-set+json", 65_536),
        ("wrong_type", 200, "application/jwk-set+json", 65_536),
        ("wrong_use", 200, "application/jwk-set+json", 65_536),
        ("wrong_alg", 200, "application/jwk-set+json", 65_536),
        ("malformed_key", 200, "application/jwk-set+json", 65_536),
        ("too_many", 200, "application/jwk-set+json", 65_536),
        ("malformed_json", 200, "application/jwk-set+json", 65_536),
        ("oversized", 200, "application/jwk-set+json", 1024),
        ("valid", 302, "application/jwk-set+json", 65_536),
        ("valid", 200, "text/html", 65_536),
    ],
)
def test_initial_invalid_jwks_is_not_ready(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    mode: str,
    status: int,
    content_type: str,
    response_limit: int,
) -> None:
    fake_cognito.jwks_mode = mode
    fake_cognito.jwks_status = status
    fake_cognito.jwks_content_type = content_type
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        upstream_max_response_bytes=response_limit,
    )
    try:
        assert cache.ready() is False
        assert cache.snapshot is None
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize("mode", ["invalid_utf8", "deep_json"])
def test_malformed_encoding_or_depth_cannot_wedge_initial_load_and_recovers(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito, mode: str
) -> None:
    clock = MonotonicClock()
    metrics = RecordingJwksMetrics()
    fake_cognito.jwks_mode = mode
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        metrics=metrics,
    )
    try:
        assert cache.ready() is False
        assert cache.snapshot is None
        assert cache._refreshing is False
        assert metrics.fetch_outcomes == ["malformed"]

        fake_cognito.jwks_mode = "valid"
        clock.advance(5)
        assert cache.ready() is True
        assert cache.snapshot is not None
        assert cache._refreshing is False
        assert metrics.fetch_outcomes == ["malformed", "success"]
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize("mode", ["invalid_utf8", "deep_json"])
def test_malformed_encoding_or_depth_preserves_snapshot_and_later_recovers(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito, mode: str
) -> None:
    clock = MonotonicClock()
    metrics = RecordingJwksMetrics()
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        metrics=metrics,
    )
    try:
        assert cache.ready()
        original = cache.snapshot
        fake_cognito.jwks_mode = mode
        clock.advance(11)
        assert cache.ready()
        assert cache.snapshot is original
        assert cache._refreshing is False
        assert metrics.cache_states[-1] == "degraded"

        fake_cognito.jwks_mode = "valid"
        clock.advance(5)
        assert cache.ready()
        assert cache.snapshot is not original
        assert cache._refreshing is False
        assert metrics.cache_states[-1] == "fresh"
    finally:
        cache.close()
        client.close()


def test_unexpected_fetch_exception_cleans_state_and_allows_immediate_recovery(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    failing = True

    def handler(request: httpx2.Request) -> httpx2.Response:
        if failing:
            raise RuntimeError("synthetic fetch failure")
        return fake_cognito.handle(request)

    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        transport=httpx2.MockTransport(handler),
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic fetch failure"):
            cache.ready()
        assert cache._refreshing is False
        failing = False
        assert cache.ready()
        assert cache._refreshing is False
    finally:
        cache.close()
        client.close()


def test_metrics_failure_cannot_prevent_refresh_state_cleanup(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    metrics = ExplodingFetchMetrics()
    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        metrics=metrics,
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic metrics failure"):
            cache.ready()
        assert cache._refreshing is False
        assert cache.snapshot is not None
        assert cache.ready() is True
    finally:
        cache.close()
        client.close()


def test_multiple_waiters_are_released_after_malformed_refresh(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    entered = threading.Event()
    release = threading.Event()
    block_refresh = False

    def handler(request: httpx2.Request) -> httpx2.Response:
        if block_refresh:
            entered.set()
            assert release.wait(timeout=2)
        return fake_cognito.handle(request)

    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        clock=clock,
        transport=httpx2.MockTransport(handler),
    )
    try:
        assert cache.ready()
        original = cache.snapshot
        fake_cognito.jwks_mode = "invalid_utf8"
        clock.advance(11)
        block_refresh = True
        barrier = threading.Barrier(20)

        def ready() -> bool:
            barrier.wait()
            return cache.ready()

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(ready) for _ in range(20)]
            assert entered.wait(timeout=1)
            release.set()
            assert [future.result(timeout=2) for future in futures] == [True] * 20
        assert fake_cognito.jwks_fetches == 2
        assert cache.snapshot is original
        assert cache._refreshing is False
    finally:
        release.set()
        cache.close()
        client.close()


def test_jwks_key_operation_metadata_accepts_only_public_signature_verification(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    fake_cognito.jwks_mode = "key_ops_verify"
    client, cache, _ = _components(settings_factory, fake_cognito)
    try:
        assert cache.ready()
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize(
    "mode",
    [
        "key_ops_encrypt",
        "key_ops_sign",
        "key_ops_duplicate",
        "key_ops_wrong_type",
        "private_key_material",
    ],
)
def test_jwks_rejects_contradictory_key_operations_and_private_material(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito, mode: str
) -> None:
    fake_cognito.jwks_mode = mode
    client, cache, _ = _components(settings_factory, fake_cognito)
    try:
        assert cache.ready() is False
        assert cache.snapshot is None
        assert cache._refreshing is False
    finally:
        cache.close()
        client.close()


def test_random_key_storm_has_bounded_fetches_and_negative_memory(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    clock = MonotonicClock()
    client, cache, verifier = _components(settings_factory, fake_cognito, clock=clock)
    try:
        verifier.verify_access_token(fake_cognito.token())
        for index in range(200):
            with pytest.raises(InvalidTokenError):
                cache.get_key(f"random-key-{index}")
        assert fake_cognito.jwks_fetches == 2
        assert cache.negative_cache_size <= 64
    finally:
        cache.close()
        client.close()


def test_fifty_rotated_key_validations_share_one_refresh(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    client, cache, verifier = _components(settings_factory, fake_cognito)
    try:
        verifier.verify_access_token(fake_cognito.token())
        rotated = fake_cognito.rotate()
        token = fake_cognito.token(key_id=rotated)
        fake_cognito.jwks_delay_seconds = 0.05
        with ThreadPoolExecutor(max_workers=50) as executor:
            subjects = list(
                executor.map(lambda _: verifier.verify_access_token(token).subject, range(50))
            )
    finally:
        cache.close()
        client.close()
    assert subjects == ["opaque-Subject_1"] * 50
    assert fake_cognito.jwks_fetches == 2


def test_concurrent_readiness_and_token_validation_share_initial_refresh(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    client, cache, verifier = _components(settings_factory, fake_cognito)
    token = fake_cognito.token()
    barrier = threading.Barrier(50)

    def validate(index: int) -> bool:
        barrier.wait()
        if index % 2 == 0:
            return cache.ready()
        return verifier.verify_access_token(token).subject == "opaque-Subject_1"

    fake_cognito.jwks_delay_seconds = 0.05
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            outcomes = list(executor.map(validate, range(50)))
    finally:
        cache.close()
        client.close()
    assert outcomes == [True] * 50
    assert fake_cognito.jwks_fetches == 1


def test_network_io_does_not_hold_cache_lock_and_shutdown_releases_waiters(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def handler(request: httpx2.Request) -> httpx2.Response:
        entered.set()
        assert release.wait(timeout=2)
        return fake_cognito.handle(request)

    client, cache, _ = _components(
        settings_factory,
        fake_cognito,
        transport=httpx2.MockTransport(handler),
    )
    outcomes: list[bool] = []
    first = threading.Thread(target=lambda: outcomes.append(cache.ready()))
    second = threading.Thread(target=lambda: outcomes.append(cache.ready()))
    try:
        first.start()
        assert entered.wait(timeout=1)
        second.start()
        started = time.monotonic()
        cache.close()
        assert time.monotonic() - started < 0.2
        release.set()
        first.join(timeout=2)
        second.join(timeout=2)
    finally:
        release.set()
        cache.close()
        client.close()
    assert not first.is_alive()
    assert not second.is_alive()
    assert outcomes == [False, False]
    assert cache._refreshing is False
    assert cache.snapshot is None
    assert cache.ready() is False
