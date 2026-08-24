from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

import httpx2
import pytest

from identity_service.config import Settings
from identity_service.security import (
    AccessTokenVerifier,
    CognitoUserInfoClient,
    JwksCache,
    UpstreamHttpClient,
)
from identity_service.security.contracts import VerifiedAccessToken
from identity_service.security.errors import (
    InsufficientScopeError,
    UserInfoResponseError,
    UserInfoTokenRejectedError,
    UserInfoUnavailableError,
)
from tests.fixtures.fake_cognito import FakeCognito


@contextmanager
def _stack(
    settings_factory: Callable[..., Settings], fake: FakeCognito
) -> Iterator[tuple[str, VerifiedAccessToken, CognitoUserInfoClient]]:
    settings = settings_factory(**fake.settings_overrides())
    client = UpstreamHttpClient(settings, transport=fake.transport())
    cache = JwksCache(settings, client)
    verifier = AccessTokenVerifier(settings, cache)
    raw_token = fake.token()
    verified = verifier.verify_access_token(raw_token)
    try:
        yield raw_token, verified, CognitoUserInfoClient(settings, client)
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize(
    ("verification", "expected"),
    [(True, True), (False, False), ("true", True), ("false", False)],
)
def test_userinfo_accepts_cognito_boolean_and_exact_string_verification(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    verification: bool | str,
    expected: bool,
) -> None:
    assert isinstance(fake_cognito.userinfo_document, dict)
    fake_cognito.userinfo_document["email_verified"] = verification
    with _stack(settings_factory, fake_cognito) as (raw, verified, userinfo):
        profile = userinfo.fetch_userinfo(raw, verified)
    assert profile.email_verified is expected
    assert profile.email == "person@example.test"
    assert profile.display_name == "Person Example"
    assert profile.avatar_url == "https://images.example.test/person.png"
    assert fake_cognito.authorization_seen


def test_missing_userinfo_verification_and_optional_claims_clear_snapshot(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    fake_cognito.userinfo_document = {"sub": "opaque-Subject_1"}
    with _stack(settings_factory, fake_cognito) as (raw, verified, userinfo):
        profile = userinfo.fetch_userinfo(raw, verified)
    assert profile.email is None
    assert profile.email_verified is False
    assert profile.display_name is None
    assert profile.avatar_url is None


@pytest.mark.parametrize("verification", [None, 1, 0, [], {}, "TRUE", "False"])
def test_userinfo_rejects_invalid_verification_claim_types(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    verification: object,
) -> None:
    assert isinstance(fake_cognito.userinfo_document, dict)
    fake_cognito.userinfo_document["email_verified"] = verification
    with (
        _stack(settings_factory, fake_cognito) as (raw, verified, userinfo),
        pytest.raises(UserInfoResponseError),
    ):
        userinfo.fetch_userinfo(raw, verified)


@pytest.mark.parametrize("subject", [None, "", "different", 42, ["opaque-Subject_1"]])
def test_userinfo_requires_exact_case_sensitive_subject_match(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito, subject: object
) -> None:
    assert isinstance(fake_cognito.userinfo_document, dict)
    fake_cognito.userinfo_document["sub"] = subject
    with (
        _stack(settings_factory, fake_cognito) as (raw, verified, userinfo),
        pytest.raises(UserInfoResponseError),
    ):
        userinfo.fetch_userinfo(raw, verified)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, UserInfoTokenRejectedError),
        (401, UserInfoTokenRejectedError),
        (403, UserInfoTokenRejectedError),
        (429, UserInfoUnavailableError),
        (500, UserInfoUnavailableError),
        (503, UserInfoUnavailableError),
        (302, UserInfoResponseError),
        (418, UserInfoResponseError),
    ],
)
def test_userinfo_statuses_map_to_typed_safe_outcomes(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    status: int,
    expected: type[Exception],
) -> None:
    fake_cognito.userinfo_status = status
    with (
        _stack(settings_factory, fake_cognito) as (raw, verified, userinfo),
        pytest.raises(expected) as captured,
    ):
        userinfo.fetch_userinfo(raw, verified)
    assert raw not in str(captured.value)


def test_userinfo_rate_limit_retains_only_bounded_retry_after(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    fake_cognito.userinfo_status = 429
    with (
        _stack(settings_factory, fake_cognito) as (raw, verified, userinfo),
        pytest.raises(UserInfoUnavailableError) as captured,
    ):
        userinfo.fetch_userinfo(raw, verified)
    assert captured.value.retry_after_seconds == 30


@pytest.mark.parametrize(
    "retry_after",
    ["9" * 5000, "-1", "Wed, 21 Oct 2015 07:28:00 GMT", "301", " 30"],
)
def test_userinfo_retry_after_parsing_is_bounded_and_decimal_only(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    retry_after: str,
) -> None:
    fake_cognito.userinfo_status = 429
    fake_cognito.retry_after = retry_after
    with (
        _stack(settings_factory, fake_cognito) as (raw, verified, userinfo),
        pytest.raises(UserInfoUnavailableError) as captured,
    ):
        userinfo.fetch_userinfo(raw, verified)
    assert captured.value.retry_after_seconds is None


@pytest.mark.parametrize(
    ("document", "content_type"),
    [
        ("malformed_json", "application/json"),
        ("invalid_utf8", "application/json"),
        ("deep_json", "application/json"),
        ("oversized", "application/json"),
        ([], "application/json"),
        ({"sub": "opaque-Subject_1", "email": 42}, "application/json"),
        ({"sub": "opaque-Subject_1", "email_verified": True}, "application/json"),
        ({"sub": "opaque-Subject_1"}, "text/html"),
    ],
)
def test_userinfo_rejects_malformed_content_without_retaining_document(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    document: object,
    content_type: str,
) -> None:
    fake_cognito.userinfo_document = document
    fake_cognito.userinfo_content_type = content_type
    overrides = fake_cognito.settings_overrides()
    if document == "oversized":
        overrides["upstream_max_response_bytes"] = 1024
    settings = settings_factory(**overrides)
    client = UpstreamHttpClient(settings, transport=fake_cognito.transport())
    cache = JwksCache(settings, client)
    token = fake_cognito.token()
    verified = AccessTokenVerifier(settings, cache).verify_access_token(token)
    try:
        with pytest.raises(UserInfoResponseError):
            CognitoUserInfoClient(settings, client).fetch_userinfo(token, verified)
    finally:
        cache.close()
        client.close()


@pytest.mark.parametrize(
    ("document", "constant"),
    [
        ("integer_limit", "NaN"),
        ("nonfinite", "NaN"),
        ("nonfinite", "Infinity"),
        ("nonfinite", "-Infinity"),
    ],
)
def test_untrusted_userinfo_numeric_json_is_typed_and_recovers(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    document: str,
    constant: str,
) -> None:
    with _stack(settings_factory, fake_cognito) as (raw, verified, userinfo):
        fake_cognito.nonfinite_constant = constant
        fake_cognito.userinfo_document = document
        with pytest.raises(UserInfoResponseError, match="malformed JSON"):
            userinfo.fetch_userinfo(raw, verified)
        fake_cognito.userinfo_document = {"sub": verified.subject, "name": "Recovered"}
        assert userinfo.fetch_userinfo(raw, verified).display_name == "Recovered"


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("email", "person\u0085@example.test"),
        ("name", "Provider\u0085Name"),
        ("picture", "https://images.example.test/\u0085picture.png"),
    ],
)
def test_userinfo_rejects_non_ascii_unicode_control_characters(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    claim: str,
    value: str,
) -> None:
    assert isinstance(fake_cognito.userinfo_document, dict)
    fake_cognito.userinfo_document[claim] = value
    with (
        _stack(settings_factory, fake_cognito) as (raw, verified, userinfo),
        pytest.raises(UserInfoResponseError, match="invalid claims"),
    ):
        userinfo.fetch_userinfo(raw, verified)


def test_userinfo_requires_openid_before_network_call(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    settings = settings_factory(**fake_cognito.settings_overrides())
    client = UpstreamHttpClient(settings, transport=fake_cognito.transport())
    cache = JwksCache(settings, client)
    token = fake_cognito.token(claims={"scope": fake_cognito.read_scope})
    verified = AccessTokenVerifier(settings, cache).verify_access_token(token)
    try:
        with pytest.raises(InsufficientScopeError):
            CognitoUserInfoClient(settings, client).fetch_userinfo(token, verified)
    finally:
        cache.close()
        client.close()
    assert fake_cognito.userinfo_fetches == 0


@pytest.mark.parametrize("error_type", [httpx2.ReadTimeout, httpx2.ConnectError])
def test_userinfo_transport_failure_is_redacted_dependency_unavailable(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    error_type: type[httpx2.HTTPError],
) -> None:
    with _stack(settings_factory, fake_cognito) as (raw, verified, _):
        settings = settings_factory(**fake_cognito.settings_overrides())

        def fail(request: httpx2.Request) -> httpx2.Response:
            raise error_type("test-only upstream detail", request=request)

        client = UpstreamHttpClient(settings, transport=httpx2.MockTransport(fail))
        try:
            with pytest.raises(UserInfoUnavailableError) as captured:
                CognitoUserInfoClient(settings, client).fetch_userinfo(raw, verified)
        finally:
            client.close()
    assert raw not in str(captured.value)
    assert "upstream detail" not in str(captured.value)
