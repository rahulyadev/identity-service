from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Engine, func, select

from identity_service.config import Settings
from identity_service.models import Profile, ProviderIdentity, User
from identity_service.security import (
    AccessTokenVerifier,
    CognitoUserInfoClient,
    JwksCache,
    UpstreamHttpClient,
)
from identity_service.security.errors import (
    InvalidTokenError,
    UserInfoResponseError,
    UserInfoUnavailableError,
)
from identity_service.services import IdentityProfileService, ProviderIdentityInput
from tests.fixtures.fake_cognito import FakeCognito

pytestmark = pytest.mark.integration


def _counts(engine: Engine) -> tuple[int, int, int]:
    with engine.connect() as connection:
        return (
            connection.execute(select(func.count()).select_from(User)).scalar_one(),
            connection.execute(select(func.count()).select_from(ProviderIdentity)).scalar_one(),
            connection.execute(select(func.count()).select_from(Profile)).scalar_one(),
        )


@contextmanager
def _security_core(
    settings_factory: Callable[..., Settings], fake: FakeCognito
) -> Iterator[tuple[AccessTokenVerifier, CognitoUserInfoClient]]:
    settings = settings_factory(**fake.settings_overrides())
    client = UpstreamHttpClient(settings, transport=fake.transport())
    cache = JwksCache(settings, client)
    try:
        yield AccessTokenVerifier(settings, cache), CognitoUserInfoClient(settings, client)
    finally:
        cache.close()
        client.close()


def _synchronize(
    service: IdentityProfileService,
    verifier: AccessTokenVerifier,
    userinfo: CognitoUserInfoClient,
    token: str,
):
    verified = verifier.verify_access_token(token)
    provider_profile = userinfo.fetch_userinfo(token, verified)
    return service.bootstrap_identity(
        ProviderIdentityInput(
            issuer=verified.issuer,
            subject=verified.subject,
            auth_time=verified.auth_time,
        ),
        provider_profile,
    )


def test_verified_token_and_userinfo_bootstrap_stable_identity_and_sync_fields(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    identity_service: IdentityProfileService,
    runtime_engine: Engine,
) -> None:
    token = fake_cognito.token()
    with _security_core(settings_factory, fake_cognito) as (verifier, userinfo):
        first = _synchronize(identity_service, verifier, userinfo, token)
        second = _synchronize(identity_service, verifier, userinfo, token)
        assert first.user_id == second.user_id
        assert _counts(runtime_engine) == (1, 1, 1)

        assert isinstance(fake_cognito.userinfo_document, dict)
        fake_cognito.userinfo_document["email"] = "changed@example.test"
        changed = _synchronize(identity_service, verifier, userinfo, token)
        assert changed.user_id == first.user_id
        assert changed.provider_email == "changed@example.test"

        overridden = identity_service.update_display_name(changed.user_id, changed.version, "Local")
        fake_cognito.userinfo_document = {"sub": "opaque-Subject_1"}
        cleared = _synchronize(identity_service, verifier, userinfo, token)
        assert cleared.user_id == first.user_id
        assert cleared.display_name_override == overridden.display_name_override == "Local"
        assert cleared.provider_email is None
        assert cleared.provider_display_name is None
        assert cleared.provider_avatar_url is None


def test_same_userinfo_email_never_merges_distinct_subjects(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    identity_service: IdentityProfileService,
    runtime_engine: Engine,
) -> None:
    with _security_core(settings_factory, fake_cognito) as (verifier, userinfo):
        assert isinstance(fake_cognito.userinfo_document, dict)
        fake_cognito.userinfo_document["email"] = "shared@example.test"
        fake_cognito.userinfo_document["sub"] = "subject-one"
        first = _synchronize(
            identity_service,
            verifier,
            userinfo,
            fake_cognito.token(claims={"sub": "subject-one"}),
        )
        fake_cognito.userinfo_document["sub"] = "subject-two"
        second = _synchronize(
            identity_service,
            verifier,
            userinfo,
            fake_cognito.token(claims={"sub": "subject-two"}),
        )
    assert first.user_id != second.user_id
    assert _counts(runtime_engine) == (2, 2, 2)


def test_subject_mismatch_invalid_token_and_userinfo_outage_create_no_rows(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    identity_service: IdentityProfileService,
    runtime_engine: Engine,
) -> None:
    with _security_core(settings_factory, fake_cognito) as (verifier, userinfo):
        token = fake_cognito.token()
        assert isinstance(fake_cognito.userinfo_document, dict)
        fake_cognito.userinfo_document["sub"] = "mismatch"
        verified = verifier.verify_access_token(token)
        with pytest.raises(UserInfoResponseError):
            userinfo.fetch_userinfo(token, verified)
        assert _counts(runtime_engine) == (0, 0, 0)

        with pytest.raises(InvalidTokenError):
            verifier.verify_access_token(token + "corrupt")
        assert _counts(runtime_engine) == (0, 0, 0)

        fake_cognito.userinfo_document["sub"] = verified.subject
        fake_cognito.userinfo_status = 500
        with pytest.raises(UserInfoUnavailableError):
            userinfo.fetch_userinfo(token, verified)
        assert _counts(runtime_engine) == (0, 0, 0)


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        (None, "invalid_utf8"),
        (None, "deep_json"),
        (None, "integer_limit"),
        (None, "nonfinite"),
        ("email", "person\u0085@example.test"),
        ("name", "Provider\u0085Name"),
        ("picture", "https://images.example.test/\u0085picture.png"),
    ],
)
def test_malformed_userinfo_data_creates_no_identity_rows(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    identity_service: IdentityProfileService,
    runtime_engine: Engine,
    claim: str | None,
    value: str,
) -> None:
    if claim is None:
        fake_cognito.userinfo_document = value
    else:
        assert isinstance(fake_cognito.userinfo_document, dict)
        fake_cognito.userinfo_document[claim] = value
    with (
        _security_core(settings_factory, fake_cognito) as (verifier, userinfo),
        pytest.raises(UserInfoResponseError),
    ):
        _synchronize(identity_service, verifier, userinfo, fake_cognito.token())
    assert _counts(runtime_engine) == (0, 0, 0)


@pytest.mark.parametrize("document", ["integer_limit", "nonfinite"])
def test_malformed_numeric_userinfo_cannot_update_existing_identity_and_recovers(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    identity_service: IdentityProfileService,
    runtime_engine: Engine,
    document: str,
) -> None:
    token = fake_cognito.token()
    with _security_core(settings_factory, fake_cognito) as (verifier, userinfo):
        initial = _synchronize(identity_service, verifier, userinfo, token)
        fake_cognito.userinfo_document = document
        with pytest.raises(UserInfoResponseError):
            _synchronize(identity_service, verifier, userinfo, token)
        assert _counts(runtime_engine) == (1, 1, 1)
        unchanged = identity_service.get_profile_for_identity(
            fake_cognito.issuer, "opaque-Subject_1"
        )
        assert unchanged.version == initial.version
        assert unchanged.provider_email == initial.provider_email

        fake_cognito.userinfo_document = {
            "sub": "opaque-Subject_1",
            "email": "recovered@example.test",
        }
        recovered = _synchronize(identity_service, verifier, userinfo, token)
        assert recovered.provider_email == "recovered@example.test"
        assert recovered.version == initial.version + 1
