"""In-memory synthetic Cognito/token/Identity fixture for BFF validation."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from reference_bff.config import Settings
from reference_bff.transactions import AuthorizationTransaction


def _base64url_uint(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


@dataclass(slots=True)
class SyntheticProvider:
    settings: Settings
    private_key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(65537, 2048)
    )
    key_id: str = "synthetic-key-1"
    subject: str = "synthetic-cognito-subject"
    code: str = "synthetic-authorization-code"
    refresh_token: str = "synthetic-refresh-token-value"
    bootstrap_status: int = 201
    jwks_status: int = 200
    token_status: int = 200
    identity_status: int = 201
    jwks_content_type: str = "application/jwk-set+json"
    token_content_type: str = "application/json"
    identity_content_type: str = "application/json"
    events: list[str] = field(default_factory=list)
    transaction: AuthorizationTransaction | None = None
    access_token: str = field(default="", repr=False)
    id_token: str = field(default="", repr=False)
    jwks_document: dict[str, Any] | None = None
    token_document: dict[str, Any] | None = None
    identity_document: dict[str, Any] | None = None

    def configure(self, transaction: AuthorizationTransaction, *, now: int | None = None) -> None:
        self.transaction = transaction
        issued_at = int(time.time()) if now is None else now
        common = {
            "iss": self.settings.cognito_issuer,
            "sub": self.subject,
            "iat": issued_at,
            "auth_time": issued_at - 1,
            "exp": issued_at + 900,
        }
        self.access_token = jwt.encode(
            {
                **common,
                "aud": self.settings.oauth_resource,
                "client_id": self.settings.client_id,
                "token_use": "access",
                "scope": " ".join(self.settings.requested_scopes),
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.key_id, "typ": "at+jwt"},
        )
        digest = hashlib.sha256(self.access_token.encode()).digest()[:16]
        at_hash = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        self.id_token = jwt.encode(
            {
                **common,
                "aud": self.settings.client_id,
                "token_use": "id",
                "nonce": transaction.nonce,
                "at_hash": at_hash,
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.key_id, "typ": "JWT"},
        )

    def public_jwk(self) -> dict[str, Any]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.key_id,
            "n": _base64url_uint(numbers.n),
            "e": _base64url_uint(numbers.e),
            "key_ops": ["verify"],
        }

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        if str(request.url) == self.settings.cognito_jwks_url and request.method == "GET":
            self.events.append("jwks")
            document = self.jwks_document or {"keys": [self.public_jwk()]}
            return httpx2.Response(
                self.jwks_status,
                request=request,
                headers={
                    "Content-Type": self.jwks_content_type,
                    "Cache-Control": "public, max-age=300",
                },
                content=json.dumps(document).encode(),
            )
        if str(request.url) == self.settings.token_endpoint and request.method == "POST":
            self.events.append("token")
            if self.transaction is None:
                raise AssertionError("synthetic provider transaction is not configured")
            expected_basic = base64.b64encode(
                (
                    f"{self.settings.client_id}:{self.settings.client_secret.get_secret_value()}"
                ).encode()
            ).decode()
            form = parse_qs(request.content.decode(), strict_parsing=True)
            expected_form = {
                "grant_type": ["authorization_code"],
                "client_id": [self.settings.client_id],
                "code": [self.code],
                "redirect_uri": [self.settings.callback_uri],
                "code_verifier": [self.transaction.pkce_verifier],
            }
            if (
                request.headers.get("authorization") != f"Basic {expected_basic}"
                or form != expected_form
            ):
                return httpx2.Response(401, request=request, json={"error": "invalid_grant"})
            document = self.token_document or {
                "access_token": self.access_token,
                "id_token": self.id_token,
                "refresh_token": self.refresh_token,
                "token_type": "Bearer",
                "expires_in": 900,
            }
            return httpx2.Response(
                self.token_status,
                request=request,
                headers={"Content-Type": self.token_content_type},
                content=json.dumps(document).encode(),
            )
        if (
            str(request.url) == self.settings.identity_api_origin + "/v1/me"
            and request.method == "PUT"
        ):
            self.events.append("identity")
            if (
                request.content
                or request.headers.get("authorization") != f"Bearer {self.access_token}"
            ):
                return httpx2.Response(400, request=request, json={"error": "invalid_request"})
            now = "2026-08-25T00:00:00+00:00"
            document = self.identity_document or {
                "user_id": str(uuid.UUID("1526af3c-c76a-4e01-a507-347205fb3c93")),
                "email": "synthetic@example.invalid",
                "email_verified": True,
                "display_name": None,
                "avatar_url": None,
                "version": 1,
                "created_at": now,
                "updated_at": now,
            }
            return httpx2.Response(
                self.identity_status,
                request=request,
                headers={"Content-Type": self.identity_content_type},
                content=json.dumps(document).encode(),
            )
        return httpx2.Response(404, request=request, json={"error": "not_found"})
