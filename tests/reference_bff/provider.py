"""In-memory synthetic Cognito/token/Identity fixture for BFF validation."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
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
    rotated_refresh_token: str = "synthetic-rotated-refresh-token-value"
    token_family_id: str = "synthetic-token-family"
    bootstrap_status: int = 201
    jwks_status: int = 200
    token_status: int = 200
    identity_status: int = 201
    profile_status: int = 200
    patch_status: int = 200
    jwks_content_type: str = "application/jwk-set+json"
    token_content_type: str = "application/json"
    identity_content_type: str = "application/json"
    refresh_status: int = 200
    revoke_status: int = 200
    revoke_body: bytes = b""
    refresh_content_type: str = "application/json"
    identity_etag: str = '"v1"'
    profile_version: int = 1
    profile_display_name: str | None = None
    events: list[str] = field(default_factory=list)
    transaction: AuthorizationTransaction | None = None
    access_token: str = field(default="", repr=False)
    id_token: str = field(default="", repr=False)
    rotated_access_token: str = field(default="", repr=False)
    rotated_id_token: str = field(default="", repr=False)
    jwks_document: dict[str, Any] | None = None
    token_document: dict[str, Any] | None = None
    identity_document: dict[str, Any] | None = None
    refresh_document: dict[str, Any] | None = None
    refresh_requests: int = 0
    revoke_requests: int = 0
    revoke_requests_seen: list[dict[str, object]] = field(default_factory=list, repr=False)
    patch_requests: list[dict[str, object]] = field(default_factory=list, repr=False)
    profile_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def configure(
        self,
        transaction: AuthorizationTransaction,
        *,
        now: int | None = None,
        access_lifetime: int = 900,
    ) -> None:
        self.transaction = transaction
        issued_at = int(time.time()) if now is None else now
        self.access_token, self.id_token = self._token_pair(
            issued_at=issued_at,
            lifetime=access_lifetime,
            nonce=transaction.nonce,
            token_id="initial-token",
        )
        self.rotated_access_token, self.rotated_id_token = self._token_pair(
            issued_at=issued_at,
            lifetime=900,
            nonce=None,
            token_id="rotated-token",
        )

    def _token_pair(
        self,
        *,
        issued_at: int,
        lifetime: int,
        nonce: str | None,
        token_id: str,
    ) -> tuple[str, str]:
        common = {
            "iss": self.settings.cognito_issuer,
            "sub": self.subject,
            "iat": issued_at,
            "auth_time": issued_at - 1,
            "exp": issued_at + lifetime,
            "origin_jti": self.token_family_id,
            "jti": token_id,
        }
        access_token = jwt.encode(
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
        digest = hashlib.sha256(access_token.encode()).digest()[:16]
        at_hash = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        id_claims = {
            **common,
            "aud": self.settings.client_id,
            "token_use": "id",
            "at_hash": at_hash,
        }
        if nonce is not None:
            id_claims["nonce"] = nonce
        id_token = jwt.encode(
            id_claims,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.key_id, "typ": "JWT"},
        )
        return access_token, id_token

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
            if self.transaction is None:
                raise AssertionError("synthetic provider transaction is not configured")
            expected_basic = base64.b64encode(
                (
                    f"{self.settings.client_id}:{self.settings.client_secret.get_secret_value()}"
                ).encode()
            ).decode()
            form = parse_qs(request.content.decode(), strict_parsing=True)
            if form.get("grant_type") == ["refresh_token"]:
                self.events.append("refresh")
                self.refresh_requests += 1
                expected_refresh = {
                    "grant_type": ["refresh_token"],
                    "client_id": [self.settings.client_id],
                    "refresh_token": [self.refresh_token],
                }
                if (
                    request.headers.get("authorization") != f"Basic {expected_basic}"
                    or form != expected_refresh
                ):
                    return httpx2.Response(401, request=request, json={"error": "invalid_grant"})
                refresh_document = self.refresh_document or {
                    "access_token": self.rotated_access_token,
                    "id_token": self.rotated_id_token,
                    "refresh_token": self.rotated_refresh_token,
                    "token_type": "Bearer",
                    "expires_in": 900,
                }
                return httpx2.Response(
                    self.refresh_status,
                    request=request,
                    headers={"Content-Type": self.refresh_content_type},
                    content=json.dumps(refresh_document).encode(),
                )
            self.events.append("token")
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
        if str(request.url) == self.settings.revocation_endpoint and request.method == "POST":
            self.events.append("revoke")
            self.revoke_requests += 1
            expected_basic = base64.b64encode(
                (
                    f"{self.settings.client_id}:{self.settings.client_secret.get_secret_value()}"
                ).encode()
            ).decode()
            form = parse_qs(request.content.decode(), strict_parsing=True)
            self.revoke_requests_seen.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "content_type": request.headers.get("content-type"),
                    "form": form,
                    "cookie": request.headers.get("cookie"),
                }
            )
            if (
                request.headers.get("authorization") != f"Basic {expected_basic}"
                or request.headers.get("content-type") != "application/x-www-form-urlencoded"
                or form != {"token": [self.refresh_token]}
                or "client_id" in form
                or request.headers.get("cookie") is not None
            ):
                return httpx2.Response(401, request=request, json={"error": "invalid_client"})
            return httpx2.Response(
                self.revoke_status,
                request=request,
                content=self.revoke_body,
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
        if (
            str(request.url) == self.settings.identity_api_origin + "/v1/me"
            and request.method == "GET"
        ):
            self.events.append("profile")
            accepted_tokens = {self.access_token, self.rotated_access_token}
            if (
                request.content
                or request.headers.get("authorization", "").removeprefix("Bearer ")
                not in accepted_tokens
                or "cookie" in request.headers
                or request.headers.get("accept") != "application/json"
            ):
                return httpx2.Response(400, request=request, json={"error": "invalid_request"})
            now = "2026-08-25T00:00:00+00:00"
            document = self.identity_document or {
                "user_id": "1526af3c-c76a-4e01-a507-347205fb3c93",
                "email": "synthetic@example.invalid",
                "email_verified": True,
                "display_name": self.profile_display_name,
                "avatar_url": None,
                "version": self.profile_version,
                "created_at": now,
                "updated_at": now,
            }
            return httpx2.Response(
                self.profile_status,
                request=request,
                headers={
                    "Content-Type": self.identity_content_type,
                    "ETag": (
                        self.identity_etag
                        if self.identity_etag != '"v1"' or self.profile_version == 1
                        else f'"v{self.profile_version}"'
                    ),
                },
                content=json.dumps(document).encode(),
            )
        if (
            str(request.url) == self.settings.identity_api_origin + "/v1/me"
            and request.method == "PATCH"
        ):
            self.events.append("profile_patch")
            accepted_tokens = {self.access_token, self.rotated_access_token}
            forwarded: dict[str, object] = {
                "authorization": request.headers.get("authorization"),
                "accept": request.headers.get("accept"),
                "content-type": request.headers.get("content-type"),
                "if-match": request.headers.get("if-match"),
                "cookie": request.headers.get("cookie"),
                "origin": request.headers.get("origin"),
                "sec-fetch-site": request.headers.get("sec-fetch-site"),
                "x-csrf-token": request.headers.get("x-csrf-token"),
                "x-request-id": request.headers.get("x-request-id"),
                "body": bytes(request.content),
            }
            self.patch_requests.append(forwarded)
            if (
                request.headers.get("authorization", "").removeprefix("Bearer ")
                not in accepted_tokens
                or request.headers.get("accept") != "application/json"
                or request.headers.get("content-type") != "application/merge-patch+json"
                or any(
                    request.headers.get(name) is not None
                    for name in (
                        "cookie",
                        "origin",
                        "sec-fetch-site",
                        "x-csrf-token",
                        "x-request-id",
                    )
                )
            ):
                return httpx2.Response(400, request=request, json={"error": "invalid_request"})
            if self.patch_status != 200:
                return httpx2.Response(
                    self.patch_status,
                    request=request,
                    headers={"Content-Type": self.identity_content_type},
                    json={"error": "synthetic_failure"},
                )
            try:
                patch = json.loads(request.content)
            except json.JSONDecodeError:
                return httpx2.Response(400, request=request, json={"error": "invalid_request"})
            if set(patch) != {"display_name"} or not (
                patch["display_name"] is None or isinstance(patch["display_name"], str)
            ):
                return httpx2.Response(400, request=request, json={"error": "invalid_request"})
            with self.profile_lock:
                if request.headers.get("if-match") != f'"v{self.profile_version}"':
                    return httpx2.Response(
                        412,
                        request=request,
                        headers={"Content-Type": "application/problem+json"},
                        json={"error": "stale"},
                    )
                self.profile_display_name = patch["display_name"]
                self.profile_version += 1
                version = self.profile_version
                display_name = self.profile_display_name
            now = "2026-08-25T00:00:00+00:00"
            document = self.identity_document or {
                "user_id": "1526af3c-c76a-4e01-a507-347205fb3c93",
                "email": "synthetic@example.invalid",
                "email_verified": True,
                "display_name": display_name,
                "avatar_url": None,
                "version": version,
                "created_at": now,
                "updated_at": now,
            }
            return httpx2.Response(
                200,
                request=request,
                headers={
                    "Content-Type": self.identity_content_type,
                    "ETag": f'"v{version}"',
                },
                content=json.dumps(document).encode(),
            )
        return httpx2.Response(404, request=request, json={"error": "not_found"})
