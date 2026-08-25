"""Minimal in-memory Cognito JWKS/UserInfo fixture with ephemeral RSA keys."""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Mapping

import httpx2
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _base64url_uint(value: int) -> str:
    width = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(width, "big")).rstrip(b"=").decode("ascii")


class FakeCognito:
    issuer = "http://cognito.test/test-pool"
    jwks_url = issuer + "/.well-known/jwks.json"
    userinfo_url = "http://cognito.test/oauth2/userInfo"
    client_id = "fixture-client"
    resource = "identity-service://api"
    read_scope = resource + "/profile.read"
    write_scope = resource + "/profile.write"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: dict[str, rsa.RSAPrivateKey] = {}
        self.active_kid = "fixture-key-1"
        self._keys[self.active_kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwks_mode = "valid"
        self.jwks_status = 200
        self.jwks_content_type = "application/jwk-set+json"
        self.cache_control = "public, max-age=300"
        self.jwks_extra_members: dict[str, object] = {}
        self.nonfinite_constant = "NaN"
        self.jwks_delay_seconds = 0.0
        self.jwks_fetches = 0
        self.userinfo_status = 200
        self.userinfo_content_type = "application/json"
        self.retry_after = "30"
        self.userinfo_delay_seconds = 0.0
        self.userinfo_document: object = {
            "sub": "opaque-Subject_1",
            "email": "person@example.test",
            "email_verified": True,
            "name": "Person Example",
            "picture": "https://images.example.test/person.png",
        }
        self.userinfo_fetches = 0
        self.authorization_seen = False

    def settings_overrides(self) -> dict[str, object]:
        return {
            "cognito_issuer": self.issuer,
            "cognito_jwks_url": self.jwks_url,
            "cognito_userinfo_url": self.userinfo_url,
            "cognito_allowed_client_ids": [self.client_id],
            "oauth_resource": self.resource,
            "oauth_profile_read_scope": self.read_scope,
            "oauth_profile_write_scope": self.write_scope,
        }

    def rotate(
        self,
        key_id: str = "fixture-key-2",
        *,
        retain_old: bool = True,
        key_size: int = 2048,
    ) -> str:
        with self._lock:
            if not retain_old:
                self._keys.clear()
            self._keys[key_id] = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            self.active_kid = key_id
        return key_id

    def compact_jws(
        self,
        *,
        header_json: bytes,
        payload_json: bytes,
        key_id: str | None = None,
    ) -> str:
        """Sign caller-supplied test JSON without adding a production decoder."""
        selected_kid = key_id or self.active_kid
        encoded_header = base64.urlsafe_b64encode(header_json).rstrip(b"=")
        encoded_payload = base64.urlsafe_b64encode(payload_json).rstrip(b"=")
        signing_input = encoded_header + b"." + encoded_payload
        signature = self._keys[selected_kid].sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
        return (signing_input + b"." + encoded_signature).decode("ascii")

    def public_jwk(self, key_id: str) -> dict[str, str]:
        numbers = self._keys[key_id].public_key().public_numbers()
        return {
            "kty": "RSA",
            "kid": key_id,
            "use": "sig",
            "alg": "RS256",
            "n": _base64url_uint(numbers.n),
            "e": _base64url_uint(numbers.e),
        }

    def token(
        self,
        *,
        key_id: str | None = None,
        claims: Mapping[str, object] | None = None,
        headers: Mapping[str, object] | None = None,
        drop_claims: tuple[str, ...] = (),
        signing_key: rsa.RSAPrivateKey | None = None,
        algorithm: str = "RS256",
    ) -> str:
        now = int(time.time())
        payload: dict[str, object] = {
            "iss": self.issuer,
            "sub": "opaque-Subject_1",
            "client_id": self.client_id,
            "aud": self.resource,
            "token_use": "access",
            "scope": f"openid {self.read_scope} {self.write_scope}",
            "exp": now + 3600,
            "iat": now,
            "auth_time": now - 10,
        }
        payload.update(claims or {})
        for claim in drop_claims:
            payload.pop(claim, None)
        selected_kid = key_id or self.active_kid
        protected: dict[str, object] = {"kid": selected_kid, "typ": "JWT"}
        protected.update(headers or {})
        if protected.get("kid") is None:
            protected.pop("kid")
        key: object = signing_key or self._keys.get(selected_kid) or self._keys[self.active_kid]
        if algorithm == "none":
            key = None
        return jwt.encode(payload, key, algorithm=algorithm, headers=protected)

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handle)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/.well-known/jwks.json"):
            return self._jwks_response(request)
        if request.url.path == "/oauth2/userInfo":
            return self._userinfo_response(request)
        return httpx2.Response(404, request=request, json={"error": "not_found"})

    def _jwks_response(self, request: httpx2.Request) -> httpx2.Response:
        with self._lock:
            self.jwks_fetches += 1
            mode = self.jwks_mode
            keys = [self.public_jwk(key_id) for key_id in self._keys]
        if self.jwks_delay_seconds:
            time.sleep(self.jwks_delay_seconds)
        if self.jwks_status != 200:
            return httpx2.Response(self.jwks_status, request=request, json={"error": "unavailable"})
        if mode == "malformed_json":
            return httpx2.Response(
                200,
                request=request,
                content=b"{",
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "invalid_utf8":
            return httpx2.Response(
                200,
                request=request,
                content=b'{"keys":["\xff"]}',
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "deep_json":
            return httpx2.Response(
                200,
                request=request,
                content=b"[" * 2000 + b"0" + b"]" * 2000,
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "integer_limit":
            prefix = json.dumps({"keys": keys}, separators=(",", ":")).encode()[:-1]
            return httpx2.Response(
                200,
                request=request,
                content=prefix + b',"metadata":' + b"9" * 5000 + b"}",
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "nonfinite":
            prefix = json.dumps({"keys": keys}, separators=(",", ":")).encode()[:-1]
            return httpx2.Response(
                200,
                request=request,
                content=prefix + b',"metadata":' + self.nonfinite_constant.encode() + b"}",
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "missing_keys":
            return httpx2.Response(
                200,
                request=request,
                json={"metadata": "ignored"},
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "keys_wrong_type":
            return httpx2.Response(
                200,
                request=request,
                json={"keys": {"kid": self.active_kid}},
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "oversized":
            return httpx2.Response(
                200,
                request=request,
                content=b"{" + b" " * 100_000,
                headers={"Content-Type": self.jwks_content_type},
            )
        if mode == "empty":
            keys = []
        elif mode == "duplicate":
            keys.append(dict(keys[0]))
        elif mode == "wrong_type":
            keys[0]["kty"] = "oct"
        elif mode == "wrong_use":
            keys[0]["use"] = "enc"
        elif mode == "wrong_alg":
            keys[0]["alg"] = "RS512"
        elif mode == "key_ops_verify":
            keys[0]["key_ops"] = ["verify"]
        elif mode == "key_ops_encrypt":
            keys[0]["key_ops"] = ["encrypt"]
        elif mode == "key_ops_sign":
            keys[0]["key_ops"] = ["sign"]
        elif mode == "key_ops_duplicate":
            keys[0]["key_ops"] = ["verify", "verify"]
        elif mode == "key_ops_wrong_type":
            keys[0]["key_ops"] = "verify"
        elif mode == "private_key_material":
            keys[0]["d"] = "AA"
        elif mode == "malformed_key":
            keys[0].pop("n")
        elif mode == "too_many":
            keys = [dict(keys[0], kid=f"excess-{index}") for index in range(100)]
        return httpx2.Response(
            200,
            request=request,
            content=json.dumps({"keys": keys, **self.jwks_extra_members}).encode(),
            headers={
                "Content-Type": self.jwks_content_type,
                "Cache-Control": self.cache_control,
            },
        )

    def _userinfo_response(self, request: httpx2.Request) -> httpx2.Response:
        with self._lock:
            self.userinfo_fetches += 1
            self.authorization_seen = request.headers.get("authorization", "").startswith("Bearer ")
        if self.userinfo_delay_seconds:
            time.sleep(self.userinfo_delay_seconds)
        if self.userinfo_status != 200:
            headers = {"Retry-After": self.retry_after} if self.userinfo_status == 429 else {}
            return httpx2.Response(
                self.userinfo_status,
                request=request,
                headers=headers,
                json={"error": "provider_error"},
            )
        if self.userinfo_document == "malformed_json":
            content = b"{"
        elif self.userinfo_document == "invalid_utf8":
            content = b'{"sub":"\xff"}'
        elif self.userinfo_document == "deep_json":
            content = b"[" * 2000 + b"0" + b"]" * 2000
        elif self.userinfo_document == "integer_limit":
            content = b'{"sub":"opaque-Subject_1","metadata":' + b"9" * 5000 + b"}"
        elif self.userinfo_document == "nonfinite":
            content = (
                b'{"sub":"opaque-Subject_1","metadata":' + self.nonfinite_constant.encode() + b"}"
            )
        elif self.userinfo_document == "oversized":
            content = b"{" + b" " * 100_000
        else:
            content = json.dumps(self.userinfo_document).encode()
        return httpx2.Response(
            200,
            request=request,
            content=content,
            headers={"Content-Type": self.userinfo_content_type},
        )
