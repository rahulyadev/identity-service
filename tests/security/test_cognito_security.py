from __future__ import annotations

import io
import json
import logging
from collections.abc import Callable
from pathlib import Path

from identity_service.app import create_app
from identity_service.config import Settings
from identity_service.observability import configure_logging
from identity_service.security import (
    AccessTokenVerifier,
    CognitoUserInfoClient,
    JwksCache,
    UpstreamHttpClient,
)
from tests.fixtures.fake_cognito import FakeCognito


def test_security_loggers_use_central_pipeline_and_redact_prohibited_fields(
    settings_factory: Callable[..., Settings],
) -> None:
    stream = io.StringIO()
    configure_logging(settings_factory(log_format="json"), stream=stream)
    sentinel = "security-log-sentinel"
    logging.getLogger("identity_service.security.tokens").warning(
        "verification failed for Bearer %s at https://provider.invalid/path",
        sentinel,
        extra={
            "authorization": f"Bearer {sentinel}",
            "subject": sentinel,
            "issuer": "https://issuer.invalid/pool",
            "email": "person@example.invalid",
            "outcome": "invalid_token",
            "error_type": "SyntheticVerificationError",
        },
    )
    record = json.loads(stream.getvalue())
    rendered = json.dumps(record, sort_keys=True)
    assert record["logger"] == "identity_service.security.tokens"
    assert record["outcome"] == "invalid_token"
    assert record["error_type"] == "SyntheticVerificationError"
    for prohibited in (sentinel, "provider.invalid", "issuer.invalid", "person@example.invalid"):
        assert prohibited not in rendered
    assert "[REDACTED]" in rendered


def test_full_security_flow_does_not_log_raw_bearer_or_provider_claims(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    settings = settings_factory(log_format="json", **fake_cognito.settings_overrides())
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    client = UpstreamHttpClient(settings, transport=fake_cognito.transport())
    cache = JwksCache(settings, client)
    raw_token = fake_cognito.token()
    try:
        verified = AccessTokenVerifier(settings, cache).verify_access_token(raw_token)
        profile = CognitoUserInfoClient(settings, client).fetch_userinfo(raw_token, verified)
        logging.getLogger("identity_service.security.tokens").warning(
            "verified contract object: %s", verified
        )
    finally:
        cache.close()
        client.close()
    rendered = stream.getvalue()
    assert raw_token not in rendered
    assert verified.subject not in rendered
    assert profile.email not in rendered
    assert fake_cognito.active_kid not in rendered
    assert verified.client_id not in rendered
    assert fake_cognito.resource not in rendered
    assert fake_cognito.read_scope not in rendered
    assert verified.key_id_fingerprint not in rendered


def test_public_bearer_contract_is_limited_to_the_profile_route(
    settings_factory: Callable[..., Settings],
) -> None:
    document = create_app(settings_factory()).openapi()
    assert set(document["paths"]) == {"/health/live", "/health/ready", "/metrics", "/v1/me"}
    assert set(document["paths"]["/v1/me"]) == {"put", "get", "patch"}
    assert set(document["components"]["securitySchemes"]) == {"BearerAuth"}
    rendered = json.dumps(document, sort_keys=True).casefold()
    assert "bearer" in rendered
    for forbidden in ("provider_email", "provider_display_name", "raw claims", "client_secret"):
        assert forbidden not in rendered


def test_runtime_security_core_has_no_cloud_sdk_or_alternative_jwt_stack() -> None:
    root = Path(__file__).resolve().parents[2]
    runtime_source = "\n".join(
        path.read_text() for path in sorted((root / "src" / "identity_service").rglob("*.py"))
    ).casefold()
    for forbidden in ("import boto3", "import botocore", "import jose", "python-jose"):
        assert forbidden not in runtime_source
    assert 'algorithms=["rs256"]' in runtime_source
    assert "jwt_algorithm" not in runtime_source


def test_runtime_image_copy_list_excludes_test_fixture_and_private_keys() -> None:
    root = Path(__file__).resolve().parents[2]
    dockerfile = (root / "Dockerfile").read_text()
    assert "COPY tests" not in dockerfile
    assert "fake_cognito" not in dockerfile
    excluded = {".git", ".venv", ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    repository_files = [
        path
        for path in root.rglob("*")
        if path.is_file() and not excluded.intersection(path.relative_to(root).parts)
    ]
    assert not any(path.suffix in {".pem", ".key"} for path in repository_files)
