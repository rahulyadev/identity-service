from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

import httpx2
import pytest
from fastapi import FastAPI
from sqlalchemy import Engine, update

from identity_service.app import create_app
from identity_service.config import Settings
from identity_service.models import User, UserStatus
from tests.fixtures.fake_cognito import FakeCognito
from tests.http_client import ASGIClient
from tests.integration.conftest import clear_identity_data

pytestmark = pytest.mark.integration
PROFILE_FIELDS = {
    "user_id",
    "email",
    "email_verified",
    "display_name",
    "avatar_url",
    "version",
    "created_at",
    "updated_at",
}


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _patch_headers(token: str, version: int) -> dict[str, str]:
    return {
        **_authorization(token),
        "Content-Type": "application/merge-patch+json",
        "If-Match": f'"v{version}"',
    }


def _assert_problem(response: httpx2.Response, status: int, code: str) -> dict[str, object]:
    assert response.status_code == status
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"type", "title", "status", "detail", "request_id", "code"}
    assert body["status"] == status
    assert body["code"] == code
    return body


@pytest.fixture
def profile_app(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    runtime_database_url: str,
    migrator_engine: Engine,
) -> Iterator[FastAPI]:
    clear_identity_data(migrator_engine)
    app = create_app(
        settings_factory(
            database_url=runtime_database_url,
            **fake_cognito.settings_overrides(),
        ),
        upstream_transport=fake_cognito.transport(),
    )
    yield app
    clear_identity_data(migrator_engine)


@pytest.fixture
def profile_client(profile_app: FastAPI) -> Iterator[ASGIClient]:
    with ASGIClient(profile_app) as client:
        yield client


def test_put_get_and_provider_sync_expose_only_minimal_profile(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token()
    created = profile_client.request("PUT", "/v1/me", headers=_authorization(token))
    assert created.status_code == 201
    assert created.headers["etag"] == '"v1"'
    assert created.headers["cache-control"] == "no-store"
    initial = created.json()
    assert set(initial) == PROFILE_FIELDS
    assert initial["version"] == 1
    assert initial["email_verified"] is True
    assert initial["display_name"] == "Person Example"
    datetime.fromisoformat(str(initial["created_at"]).replace("Z", "+00:00"))
    datetime.fromisoformat(str(initial["updated_at"]).replace("Z", "+00:00"))

    repeated = profile_client.request("PUT", "/v1/me", headers=_authorization(token))
    assert repeated.status_code == 200
    assert repeated.json() == initial
    assert repeated.headers["etag"] == '"v1"'

    userinfo_fetches = fake_cognito.userinfo_fetches
    local = profile_client.get("/v1/me", headers=_authorization(token))
    assert local.status_code == 200
    assert local.json() == initial
    assert local.headers["etag"] == '"v1"'
    assert fake_cognito.userinfo_fetches == userinfo_fetches

    assert isinstance(fake_cognito.userinfo_document, dict)
    fake_cognito.userinfo_document["email"] = "changed@example.test"
    fake_cognito.userinfo_document["name"] = "Changed Provider"
    synchronized = profile_client.request("PUT", "/v1/me", headers=_authorization(token))
    assert synchronized.status_code == 200
    changed = synchronized.json()
    assert changed["user_id"] == initial["user_id"]
    assert changed["email"] == "changed@example.test"
    assert changed["display_name"] == "Changed Provider"
    assert changed["version"] == 2
    assert synchronized.headers["etag"] == '"v2"'
    rendered = json.dumps(changed, sort_keys=True).casefold()
    for prohibited in ("issuer", "subject", "scope", "client_id", "provider_"):
        assert prohibited not in rendered
    assert token not in rendered


def test_get_before_bootstrap_is_local_404_without_userinfo(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    response = profile_client.get("/v1/me", headers=_authorization(fake_cognito.token()))
    _assert_problem(response, 404, "identity_not_initialized")
    assert fake_cognito.userinfo_fetches == 0


def test_same_email_different_subjects_are_distinct_http_identities(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    assert isinstance(fake_cognito.userinfo_document, dict)
    fake_cognito.userinfo_document["email"] = "shared@example.test"
    fake_cognito.userinfo_document["sub"] = "subject-one"
    first = profile_client.request(
        "PUT",
        "/v1/me",
        headers=_authorization(fake_cognito.token(claims={"sub": "subject-one"})),
    )
    fake_cognito.userinfo_document["sub"] = "subject-two"
    second = profile_client.request(
        "PUT",
        "/v1/me",
        headers=_authorization(fake_cognito.token(claims={"sub": "subject-two"})),
    )
    assert first.status_code == second.status_code == 201
    assert first.json()["user_id"] != second.json()["user_id"]
    assert first.json()["email"] == second.json()["email"] == "shared@example.test"


def test_patch_set_noop_clear_and_conflict(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token()
    created = profile_client.request("PUT", "/v1/me", headers=_authorization(token))
    assert created.status_code == 201

    updated = profile_client.request(
        "PATCH",
        "/v1/me",
        headers=_patch_headers(token, 1),
        content=b'{"display_name":"  Local Name  "}',
    )
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "Local Name"
    assert updated.json()["version"] == 2
    assert updated.headers["etag"] == '"v2"'

    noop = profile_client.request(
        "PATCH",
        "/v1/me",
        headers=_patch_headers(token, 2),
        content=b'{"display_name":"Local Name"}',
    )
    assert noop.status_code == 200
    assert noop.json() == updated.json()
    assert noop.headers["etag"] == '"v2"'

    stale = profile_client.request(
        "PATCH",
        "/v1/me",
        headers=_patch_headers(token, 1),
        content=b'{"display_name":"Stale"}',
    )
    _assert_problem(stale, 412, "profile_version_conflict")

    cleared = profile_client.request(
        "PATCH",
        "/v1/me",
        headers=_patch_headers(token, 2),
        content=b'{"display_name":null}',
    )
    assert cleared.status_code == 200
    assert cleared.json()["display_name"] == "Person Example"
    assert cleared.json()["version"] == 3
    assert cleared.headers["etag"] == '"v3"'


@pytest.mark.parametrize(
    "value",
    [
        'W/"v1"',
        "*",
        '"v0"',
        '"v01"',
        '"v-1"',
        ' "v1"',
        '"v1" ',
        '"v9223372036854775808"',
        '"v1", "v2"',
    ],
)
def test_patch_rejects_malformed_preconditions(
    profile_client: ASGIClient, fake_cognito: FakeCognito, value: str
) -> None:
    token = fake_cognito.token()
    assert profile_client.request("PUT", "/v1/me", headers=_authorization(token)).status_code == 201
    response = profile_client.request(
        "PATCH",
        "/v1/me",
        headers={
            **_authorization(token),
            "Content-Type": "application/merge-patch+json",
            "If-Match": value,
        },
        content=b'{"display_name":"Local"}',
    )
    _assert_problem(response, 400, "invalid_precondition")


def test_patch_distinguishes_missing_and_duplicate_preconditions(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token()
    assert profile_client.request("PUT", "/v1/me", headers=_authorization(token)).status_code == 201
    missing = profile_client.request(
        "PATCH",
        "/v1/me",
        headers={
            **_authorization(token),
            "Content-Type": "application/merge-patch+json",
        },
        content=b'{"display_name":"Local"}',
    )
    _assert_problem(missing, 428, "precondition_required")

    duplicate = profile_client.request(
        "PATCH",
        "/v1/me",
        headers=[
            ("Authorization", f"Bearer {token}"),
            ("Content-Type", "application/merge-patch+json"),
            ("If-Match", '"v1"'),
            ("If-Match", '"v1"'),
        ],
        content=b'{"display_name":"Local"}',
    )
    _assert_problem(duplicate, 400, "invalid_precondition")


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{}",
        b"[]",
        b'{"other":"Local"}',
        b'{"display_name":"Local","other":null}',
        b'{"display_name":"A","display_name":"B"}',
        b'{"display_name":1}',
        b'{"display_name":true}',
        b'{"display_name":{}}',
        b'{"display_name":"bad\\nname"}',
        b'{"display_name":"\\ud800"}',
        b'{"display_name":NaN}',
        b"{",
    ],
)
def test_patch_rejects_invalid_merge_patch_shapes(
    profile_client: ASGIClient, fake_cognito: FakeCognito, body: bytes
) -> None:
    token = fake_cognito.token()
    assert profile_client.request("PUT", "/v1/me", headers=_authorization(token)).status_code == 201
    response = profile_client.request(
        "PATCH", "/v1/me", headers=_patch_headers(token, 1), content=body
    )
    _assert_problem(response, 422, "validation_failed")


def test_patch_rejects_over_limit_name_and_wrong_or_duplicate_media_type(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token()
    assert profile_client.request("PUT", "/v1/me", headers=_authorization(token)).status_code == 201
    over_limit = profile_client.request(
        "PATCH",
        "/v1/me",
        headers=_patch_headers(token, 1),
        json={"display_name": "x" * 101},
    )
    _assert_problem(over_limit, 422, "validation_failed")

    wrong = profile_client.request(
        "PATCH",
        "/v1/me",
        headers={
            **_authorization(token),
            "Content-Type": "application/json",
            "If-Match": '"v1"',
        },
        content=b'{"display_name":"Local"}',
    )
    _assert_problem(wrong, 415, "unsupported_media_type")

    duplicate = profile_client.request(
        "PATCH",
        "/v1/me",
        headers=[
            ("Authorization", f"Bearer {token}"),
            ("Content-Type", "application/merge-patch+json"),
            ("Content-Type", "application/merge-patch+json"),
            ("If-Match", '"v1"'),
        ],
        content=b'{"display_name":"Local"}',
    )
    _assert_problem(duplicate, 415, "unsupported_media_type")


def test_put_rejects_nonempty_body_after_authentication(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    response = profile_client.request(
        "PUT",
        "/v1/me",
        headers=_authorization(fake_cognito.token()),
        content=b"{}",
    )
    _assert_problem(response, 400, "request_body_not_allowed")
    assert fake_cognito.userinfo_fetches == 0


def test_authentication_precedes_route_validation_and_uses_fixed_challenges(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    unauthenticated = profile_client.request(
        "PATCH", "/v1/me", headers={"Content-Type": "text/plain"}, content=b"invalid"
    )
    _assert_problem(unauthenticated, 401, "invalid_token")
    assert unauthenticated.headers["www-authenticate"] == (
        'Bearer realm="identity", error="invalid_token"'
    )

    read_only = fake_cognito.token(claims={"scope": f"openid {fake_cognito.read_scope}"})
    scope_failure = profile_client.request("PUT", "/v1/me", headers=_authorization(read_only))
    _assert_problem(scope_failure, 403, "insufficient_scope")
    assert scope_failure.headers["www-authenticate"] == (
        'Bearer realm="identity", error="insufficient_scope"'
    )

    missing_openid = fake_cognito.token(claims={"scope": fake_cognito.write_scope})
    _assert_problem(
        profile_client.request("PUT", "/v1/me", headers=_authorization(missing_openid)),
        403,
        "insufficient_scope",
    )
    assert fake_cognito.userinfo_fetches == 0


def test_duplicate_authorization_and_invalid_token_are_rejected_without_database_use(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token()
    duplicate = profile_client.get(
        "/v1/me",
        headers=[
            ("Authorization", f"Bearer {token}"),
            ("Authorization", f"Bearer {token}"),
        ],
    )
    _assert_problem(duplicate, 401, "invalid_token")
    corrupted = profile_client.get("/v1/me", headers=_authorization(token + "corrupt"))
    _assert_problem(corrupted, 401, "invalid_token")


@pytest.mark.parametrize("status", [UserStatus.DISABLED, UserStatus.DELETED])
def test_disabled_and_deleted_accounts_are_unavailable_on_all_profile_operations(
    profile_client: ASGIClient,
    fake_cognito: FakeCognito,
    migrator_engine: Engine,
    status: UserStatus,
) -> None:
    token = fake_cognito.token()
    created = profile_client.request("PUT", "/v1/me", headers=_authorization(token))
    user_id = created.json()["user_id"]
    values: dict[str, object] = {"status": status.value}
    if status is UserStatus.DELETED:
        values["deleted_at"] = datetime.now(UTC)
    with migrator_engine.begin() as connection:
        connection.execute(update(User).where(User.id == user_id).values(**values))

    responses = [
        profile_client.request("PUT", "/v1/me", headers=_authorization(token)),
        profile_client.get("/v1/me", headers=_authorization(token)),
        profile_client.request(
            "PATCH",
            "/v1/me",
            headers=_patch_headers(token, 1),
            content=b'{"display_name":"Blocked"}',
        ),
    ]
    for response in responses:
        _assert_problem(response, 403, "account_unavailable")


@pytest.mark.parametrize(
    ("provider_status", "expected_status", "expected_code"),
    [
        (401, 401, "invalid_token"),
        (429, 503, "provider_unavailable"),
        (500, 503, "provider_unavailable"),
    ],
)
def test_userinfo_failures_map_to_safe_contract_without_rows(
    profile_client: ASGIClient,
    fake_cognito: FakeCognito,
    provider_status: int,
    expected_status: int,
    expected_code: str,
) -> None:
    fake_cognito.userinfo_status = provider_status
    response = profile_client.request("PUT", "/v1/me", headers=_authorization(fake_cognito.token()))
    _assert_problem(response, expected_status, expected_code)
    if provider_status == 401:
        assert response.headers["www-authenticate"] == (
            'Bearer realm="identity", error="invalid_token"'
        )
    if provider_status == 429:
        assert response.headers["retry-after"] == "30"


def test_userinfo_subject_mismatch_is_safe_provider_failure(
    profile_client: ASGIClient, fake_cognito: FakeCognito
) -> None:
    assert isinstance(fake_cognito.userinfo_document, dict)
    fake_cognito.userinfo_document["sub"] = "different-subject"
    response = profile_client.request("PUT", "/v1/me", headers=_authorization(fake_cognito.token()))
    body = _assert_problem(response, 503, "provider_unavailable")
    assert "different-subject" not in json.dumps(body)


def test_jwks_outage_maps_to_authentication_unavailable(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    fake_cognito.jwks_status = 500
    app = create_app(
        settings_factory(**fake_cognito.settings_overrides()),
        upstream_transport=fake_cognito.transport(),
    )
    with ASGIClient(app) as client:
        response = client.get("/v1/me", headers=_authorization(fake_cognito.token()))
    _assert_problem(response, 503, "authentication_unavailable")


def test_database_outage_maps_to_safe_503_after_authentication(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    app = create_app(
        settings_factory(**fake_cognito.settings_overrides()),
        upstream_transport=fake_cognito.transport(),
    )
    token = fake_cognito.token()
    with ASGIClient(app) as client:
        get_response = client.get("/v1/me", headers=_authorization(token))
        put_response = client.request("PUT", "/v1/me", headers=_authorization(token))
    _assert_problem(get_response, 503, "database_unavailable")
    _assert_problem(put_response, 503, "database_unavailable")


def test_concurrent_patch_has_exactly_one_http_winner(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    runtime_database_url: str,
    migrator_engine: Engine,
) -> None:
    clear_identity_data(migrator_engine)
    app = create_app(
        settings_factory(
            database_url=runtime_database_url,
            **fake_cognito.settings_overrides(),
        ),
        upstream_transport=fake_cognito.transport(),
    )

    async def exercise() -> list[httpx2.Response]:
        async with (
            app.router.lifespan_context(app),
            httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url="http://testserver"
            ) as client,
        ):
            token = fake_cognito.token()
            created = await client.request("PUT", "/v1/me", headers=_authorization(token))
            assert created.status_code == 201

            async def update_name(index: int) -> httpx2.Response:
                return await client.request(
                    "PATCH",
                    "/v1/me",
                    headers=_patch_headers(token, 1),
                    json={"display_name": f"Name {index}"},
                )

            return await asyncio.gather(*(update_name(index) for index in range(20)))

    try:
        responses = asyncio.run(exercise())
    finally:
        clear_identity_data(migrator_engine)
    assert [response.status_code for response in responses].count(200) == 1
    assert [response.status_code for response in responses].count(412) == 19
    for response in responses:
        assert response.headers["cache-control"] == "no-store"


def test_all_profile_method_and_global_body_failures_are_no_store(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    app = create_app(
        settings_factory(
            max_request_body_bytes=32,
            **fake_cognito.settings_overrides(),
        ),
        upstream_transport=fake_cognito.transport(),
    )
    with ASGIClient(app) as client:
        method = client.request("DELETE", "/v1/me")
        oversized = client.request("PUT", "/v1/me", content=b"x" * 33)
        cors_probe = client.request(
            "OPTIONS",
            "/v1/me",
            headers={
                "Origin": "https://browser.invalid",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert method.status_code == 405
    assert method.headers["allow"]
    assert method.headers["cache-control"] == "no-store"
    assert oversized.status_code == 413
    assert oversized.headers["cache-control"] == "no-store"
    assert cors_probe.status_code == 405
    assert cors_probe.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in cors_probe.headers
