"""Exercise the packed reference BFF with disposable Redis and hardened runtime controls."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import shutil

# Every subprocess invocation is restricted to a resolved Docker executable and fixed arguments.
import subprocess  # nosec B404
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ("compose",)
SECURITY_HEADERS = {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}
FIXTURE_ORIGIN_ENVIRONMENT = "REFERENCE_BFF_FIXTURE_ORIGIN"
FIXTURE_CLIENT_ID = "synthetic-reference-client"
FIXTURE_CLIENT_SECRET = "local-reference-client-secret"  # nosec B105  # pragma: allowlist secret
FIXTURE_RESOURCE = "identity-service://api"
FIXTURE_SCOPES = "openid identity-service://api/profile.read identity-service://api/profile.write"
FIXTURE_CODE = "synthetic-authorization-code"
FIXTURE_SUBJECT = "synthetic-cognito-subject"
FIXTURE_USER_ID = "1526af3c-c76a-4e01-a507-347205fb3c93"


def base64url_uint(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


@dataclass(slots=True)
class FixtureState:
    private_key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(65537, 2048)
    )
    key_id: str = "synthetic-packed-key"
    expected_nonce: str | None = field(default=None, repr=False)
    expected_challenge: str | None = field(default=None, repr=False)
    token_available: bool = True
    identity_available: bool = True
    access_token: str = field(default="", repr=False)
    id_token: str = field(default="", repr=False)
    refresh_token: str = field(default="synthetic-packed-refresh-token", repr=False)
    issuer: str = field(default="", repr=False)
    events: list[str] = field(default_factory=list)

    def public_jwk(self) -> dict[str, Any]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.key_id,
            "n": base64url_uint(numbers.n),
            "e": base64url_uint(numbers.e),
            "key_ops": ["verify"],
        }

    def issue_tokens(self) -> None:
        if self.expected_nonce is None:
            raise RuntimeError("packed fixture nonce is absent")
        if not self.issuer:
            raise RuntimeError("packed fixture issuer is absent")
        now = int(time.time())
        common = {
            "iss": self.issuer,
            "sub": FIXTURE_SUBJECT,
            "iat": now,
            "auth_time": now - 1,
            "exp": now + 900,
        }
        self.access_token = jwt.encode(
            {
                **common,
                "aud": FIXTURE_RESOURCE,
                "client_id": FIXTURE_CLIENT_ID,
                "token_use": "access",  # nosec B105
                "scope": FIXTURE_SCOPES,
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
                "aud": FIXTURE_CLIENT_ID,
                "token_use": "id",  # nosec B105
                "nonce": self.expected_nonce,
                "at_hash": at_hash,
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.key_id, "typ": "JWT"},
        )


def fixture_handler(state: FixtureState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def _json(self, status: int, document: dict[str, Any]) -> None:
            body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/test-pool/.well-known/jwks.json":
                state.events.append("jwks")
                self._json(200, {"keys": [state.public_jwk()]})
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/oauth2/token":
                self._json(404, {"error": "not_found"})
                return
            state.events.append("token")
            if not state.token_available:
                self._json(503, {"error": "temporarily_unavailable"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
            expected_basic = base64.b64encode(
                f"{FIXTURE_CLIENT_ID}:{FIXTURE_CLIENT_SECRET}".encode()
            ).decode()
            verifier = form.get("code_verifier", [""])[0]
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            expected = {
                "grant_type": ["authorization_code"],
                "client_id": [FIXTURE_CLIENT_ID],
                "code": [FIXTURE_CODE],
                "redirect_uri": ["http://localhost:8081/auth/callback"],
                "code_verifier": [verifier],
            }
            if (
                self.headers.get("Authorization") != f"Basic {expected_basic}"
                or form != expected
                or challenge != state.expected_challenge
            ):
                self._json(400, {"error": "invalid_grant"})
                return
            state.issue_tokens()
            self._json(
                200,
                {
                    "access_token": state.access_token,
                    "id_token": state.id_token,
                    "refresh_token": state.refresh_token,
                    "token_type": "Bearer",  # nosec B105
                    "expires_in": 900,
                },
            )

        def do_PUT(self) -> None:
            if self.path != "/v1/me":
                self._json(404, {"error": "not_found"})
                return
            state.events.append("identity")
            if not state.identity_available:
                self._json(503, {"error": "unavailable"})
                return
            if self.headers.get("Authorization") != f"Bearer {state.access_token}":
                self._json(401, {"error": "invalid_token"})
                return
            now = "2026-08-25T00:00:00+00:00"
            self._json(
                201,
                {
                    "user_id": FIXTURE_USER_ID,
                    "email": "synthetic@example.invalid",
                    "email_verified": True,
                    "display_name": None,
                    "avatar_url": None,
                    "version": 1,
                    "created_at": now,
                    "updated_at": now,
                },
            )

    return Handler


def run(*arguments: str, check: bool = True) -> str:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker is required")
    result = subprocess.run(  # nosec B603
        (docker, *arguments),
        cwd=ROOT,
        check=False,
        capture_output=True,
        shell=False,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError("Docker command failed within the BFF smoke boundary")
    return result.stdout.strip()


def request(path: str, *, cookie: str | None = None) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", 8081, timeout=3)
    try:
        request_headers = {"Host": "localhost", "Connection": "close"}
        if cookie is not None:
            request_headers["Cookie"] = cookie
        connection.request("GET", path, headers=request_headers)
        response = connection.getresponse()
        body = response.read(16_385)
        headers: dict[str, str] = {}
        cookies: list[str] = []
        for name, value in response.getheaders():
            normalized = name.casefold()
            if normalized == "set-cookie":
                cookies.append(value)
            else:
                headers[normalized] = value
        if cookies:
            headers["set-cookie"] = "\n".join(cookies)
        return response.status, headers, body
    finally:
        connection.close()


def wait_for(path: str, expected_status: int, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _headers, _body = request(path)
            if status == expected_status:
                return
        except TimeoutError, ConnectionError, OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError("BFF endpoint did not reach its expected bounded state")


def assert_headers(headers: dict[str, str], *, allow_cookie: bool = False) -> None:
    if any(headers.get(name) != value for name, value in SECURITY_HEADERS.items()):
        raise RuntimeError("BFF response security headers differ")
    if any(name.startswith("access-control-") for name in headers):
        raise RuntimeError("BFF unexpectedly emitted CORS headers")
    if not allow_cookie and "set-cookie" in headers:
        raise RuntimeError("BFF unexpectedly emitted a cookie")


def set_cookies(headers: dict[str, str]) -> list[str]:
    value = headers.get("set-cookie")
    return [] if value is None else value.split("\n")


def oauth_binding_cookie(headers: dict[str, str]) -> str:
    cookies = set_cookies(headers)
    if len(cookies) != 1:
        raise RuntimeError("packed BFF login cookie count differs")
    match = re.fullmatch(
        r"__Host-oauth=([A-Za-z0-9_-]{43}); HttpOnly; Max-Age=300; "
        r"Path=/; SameSite=lax; Secure",
        cookies[0],
    )
    if match is None or "Domain=" in cookies[0]:
        raise RuntimeError("packed BFF binding cookie flags or lifetime differ")
    return match.group(1)


def assert_binding_clear(cookie: str) -> None:
    if (
        re.fullmatch(
            r'__Host-oauth=""; expires=[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} '
            r"[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT; HttpOnly; "
            r"Max-Age=0; Path=/; SameSite=lax; Secure",
            cookie,
        )
        is None
        or "Domain=" in cookie
    ):
        raise RuntimeError("packed BFF binding clearing cookie differs")


def bound_fixture_origin(server: ThreadingHTTPServer) -> str:
    address = server.server_address
    if (
        not isinstance(address, tuple)
        or len(address) < 2
        or address[0] != "127.0.0.1"
        or isinstance(address[1], bool)
        or not isinstance(address[1], int)
        or not 0 < address[1] < 65_536
    ):
        raise RuntimeError("packed fixture did not bind a valid loopback port")
    return f"http://127.0.0.1:{address[1]}"


def main() -> int:
    fixture = FixtureState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), fixture_handler(fixture))
    fixture_thread: threading.Thread | None = None
    fixture_thread_started = False
    compose_attempted = False
    previous_fixture_origin = os.environ.get(FIXTURE_ORIGIN_ENVIRONMENT)
    try:
        fixture_origin = bound_fixture_origin(server)
        fixture.issuer = f"{fixture_origin}/test-pool"
        fixture_thread = threading.Thread(target=server.serve_forever, daemon=True)
        os.environ[FIXTURE_ORIGIN_ENVIRONMENT] = fixture_origin
        fixture_thread.start()
        fixture_thread_started = True
        compose_attempted = True
        run(*COMPOSE, "up", "-d", "--wait", "redis", "bff")
        wait_for("/health/ready", 200)
        container_id = run(*COMPOSE, "ps", "-q", "bff")
        if not container_id:
            raise RuntimeError("BFF container is absent")
        container = json.loads(run("inspect", container_id))[0]
        state = container["State"]
        host_config = container["HostConfig"]
        if state.get("Health", {}).get("Status") != "healthy":
            raise RuntimeError("packed BFF did not become healthy")
        if container["Config"].get("User") != "10002:10002":
            raise RuntimeError("packed BFF user identity differs")
        if host_config.get("ReadonlyRootfs") is not True:
            raise RuntimeError("packed BFF root filesystem is not read-only")
        if "ALL" not in (host_config.get("CapDrop") or []):
            raise RuntimeError("packed BFF did not drop all capabilities")
        if "no-new-privileges:true" not in (host_config.get("SecurityOpt") or []):
            raise RuntimeError("packed BFF lacks no-new-privileges")

        tooling = json.loads(
            run(
                *COMPOSE,
                "exec",
                "-T",
                "bff",
                "python",
                "-c",
                "import importlib.util,json,os,shutil;"
                "modules=('pip','ensurepip','pytest','identity_service');"
                "names=('pip','pip3','apt','apt-get','apt-cache','dpkg','dpkg-query','dpkg-deb',"
                "'apk','yum','dnf','microdnf','rpm','npm','npx','gem','gcc','cc','make','git',"
                "'aws','gcloud','terraform','tofu');"
                "print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),"
                "'modules':{name:importlib.util.find_spec(name) is not None for name in modules},"
                "'paths':{name:shutil.which(name) for name in names}},sort_keys=True))",
            )
        )
        if tooling["uid"] != 10002 or tooling["gid"] != 10002:
            raise RuntimeError("packed BFF process is not the documented non-root identity")
        if any(tooling["modules"].values()):
            raise RuntimeError("packed BFF contains a forbidden package boundary")
        if any(tooling["paths"].values()):
            raise RuntimeError("packed BFF contains development or deployment tooling")

        live_status, live_headers, live_body = request("/health/live")
        if live_status != 200 or live_body != b'{"status":"alive"}':
            raise RuntimeError("packed BFF liveness failed")
        assert_headers(live_headers)
        login_status, login_headers, _login_body = request("/auth/login")
        if login_status != 307:
            raise RuntimeError("packed BFF login initiation failed")
        assert_headers(login_headers, allow_cookie=True)
        copied_binding = oauth_binding_cookie(login_headers)
        redirect = urlsplit(login_headers.get("location", ""))
        query = parse_qs(redirect.query, strict_parsing=True)
        if set(query) != {
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "resource",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
        }:
            raise RuntimeError("packed BFF redirect fields differ")
        if query.get("code_challenge_method") != ["S256"]:
            raise RuntimeError("packed BFF did not use PKCE S256")
        if query.get("resource") != [FIXTURE_RESOURCE]:
            raise RuntimeError("packed BFF did not bind the Identity resource")
        if re.search(r"(?i)(secret|verifier|transaction|redis|token)", redirect.query):
            raise RuntimeError("packed BFF redirect contains forbidden material")

        copied_query = query
        copied_path = (
            f"/auth/callback?code={quote(FIXTURE_CODE, safe='-._~')}&state={query['state'][0]}"
        )
        events_before_copy = list(fixture.events)
        copied_status, copied_headers, copied_body = request(copied_path)
        if (
            copied_status != 400
            or json.loads(copied_body).get("code") != "invalid_oauth_transaction"
            or "set-cookie" in copied_headers
            or fixture.events != events_before_copy
        ):
            raise RuntimeError("packed BFF accepted a copied no-cookie callback")

        login_status, login_headers, _login_body = request("/auth/login")
        if login_status != 307:
            raise RuntimeError("packed BFF matching login initiation failed")
        assert_headers(login_headers, allow_cookie=True)
        binding = oauth_binding_cookie(login_headers)
        redirect = urlsplit(login_headers.get("location", ""))
        query = parse_qs(redirect.query, strict_parsing=True)
        fixture.expected_nonce = query["nonce"][0]
        fixture.expected_challenge = query["code_challenge"][0]
        callback_path = (
            f"/auth/callback?code={quote(FIXTURE_CODE, safe='-._~')}&state={query['state'][0]}"
        )
        callback_status, callback_headers, callback_body = request(
            callback_path, cookie=f"__Host-oauth={binding}"
        )
        if callback_status != 303 or callback_headers.get("location") != "/":
            raise RuntimeError("packed BFF callback did not return the safe local redirect")
        assert_headers(callback_headers, allow_cookie=True)
        cookies = set_cookies(callback_headers)
        if len(cookies) != 2:
            raise RuntimeError("packed BFF callback cookie count differs")
        clearing_cookie = next(
            (cookie for cookie in cookies if cookie.startswith('__Host-oauth="";')),
            "",
        )
        cookie = next(
            (cookie for cookie in cookies if cookie.startswith("__Host-session=")),
            "",
        )
        assert_binding_clear(clearing_cookie)
        cookie_match = re.fullmatch(
            r"__Host-session=([A-Za-z0-9_-]{43}); HttpOnly; Max-Age=([0-9]+); "
            r"Path=/; SameSite=lax; Secure",
            cookie,
        )
        if cookie_match is None or int(cookie_match.group(2)) != 43_200:
            raise RuntimeError("packed BFF session cookie flags or lifetime differ")
        session_id = cookie_match.group(1)
        forbidden_browser_values = (
            fixture.access_token,
            fixture.id_token,
            fixture.refresh_token,
            FIXTURE_SUBJECT,
            FIXTURE_USER_ID,
            query["state"][0],
            fixture.expected_nonce,
            binding,
            copied_binding,
        )
        browser_surface = (
            callback_body.decode(errors="replace")
            + callback_headers.get("location", "")
            + "".join(cookies)
        )
        if any(value and value in browser_surface for value in forbidden_browser_values):
            raise RuntimeError("packed BFF leaked server-side identity material to the browser")
        session_digest = hashlib.sha256(
            f"reference-bff:local:compose\x00session\x00{session_id}".encode()
        ).hexdigest()
        session_key = f"reference-bff:local:compose:session:{session_digest}"
        stored_session = json.loads(
            run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "--raw", "GET", session_key)
        )
        if fixture.events[-2:] != ["token", "identity"]:
            raise RuntimeError("packed BFF did not bootstrap Identity before session inspection")
        expected_record_values = {
            "issuer": fixture.issuer,
            "subject": FIXTURE_SUBJECT,
            "client_id": FIXTURE_CLIENT_ID,
            "user_id": FIXTURE_USER_ID,
            "access_token": fixture.access_token,
            "id_token": fixture.id_token,
            "refresh_token": fixture.refresh_token,
            "refresh_version": 0,
            "version": 1,
        }
        if any(stored_session.get(key) != value for key, value in expected_record_values.items()):
            raise RuntimeError("packed BFF server-side session record differs")
        session_ttl = int(run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "TTL", session_key))
        if not 0 < session_ttl <= 43_200:
            raise RuntimeError("packed BFF session TTL exceeds the idle bound")
        replay_status, replay_headers, replay_body = request(
            callback_path, cookie=f"__Host-oauth={binding}"
        )
        if (
            replay_status != 400
            or json.loads(replay_body).get("code") != "invalid_oauth_transaction"
            or "set-cookie" in replay_headers
            or fixture.events[-2:] != ["token", "identity"]
        ):
            raise RuntimeError("packed BFF callback replay was not rejected before exchange")

        denied_login_status, denied_login_headers, _denied_login_body = request("/auth/login")
        if denied_login_status != 307:
            raise RuntimeError("packed BFF denial setup failed")
        assert_headers(denied_login_headers, allow_cookie=True)
        denied_binding = oauth_binding_cookie(denied_login_headers)
        denied_query = parse_qs(urlsplit(denied_login_headers["location"]).query)
        events_before_denial = list(fixture.events)
        denied_status, denied_headers, denied_body = request(
            f"/auth/callback?error=access_denied&state={denied_query['state'][0]}",
            cookie=f"__Host-oauth={denied_binding}",
        )
        denied_cookies = set_cookies(denied_headers)
        if (
            denied_status != 400
            or json.loads(denied_body).get("code") != "authorization_denied"
            or "access_denied" in denied_body.decode()
            or len(denied_cookies) != 1
            or fixture.events != events_before_denial
        ):
            raise RuntimeError("packed BFF provider denial crossed the fixed boundary")
        assert_binding_clear(denied_cookies[0])

        outage_login_status, outage_login_headers, _outage_login_body = request("/auth/login")
        if outage_login_status != 307:
            raise RuntimeError("packed BFF provider-outage setup failed")
        assert_headers(outage_login_headers, allow_cookie=True)
        outage_binding = oauth_binding_cookie(outage_login_headers)
        outage_query = parse_qs(urlsplit(outage_login_headers["location"]).query)
        fixture.expected_nonce = outage_query["nonce"][0]
        fixture.expected_challenge = outage_query["code_challenge"][0]
        fixture.token_available = False
        outage_status, outage_headers, outage_body = request(
            f"/auth/callback?code={FIXTURE_CODE}&state={outage_query['state'][0]}",
            cookie=f"__Host-oauth={outage_binding}",
        )
        fixture.token_available = True
        outage_cookies = set_cookies(outage_headers)
        if (
            outage_status != 503
            or json.loads(outage_body).get("code") != "authentication_unavailable"
            or len(outage_cookies) != 1
        ):
            raise RuntimeError("packed BFF provider outage did not fail without a session")
        assert_binding_clear(outage_cookies[0])

        recovery_login_status, recovery_login_headers, _recovery_login_body = request("/auth/login")
        if recovery_login_status != 307:
            raise RuntimeError("packed BFF provider recovery setup failed")
        assert_headers(recovery_login_headers, allow_cookie=True)
        recovery_binding = oauth_binding_cookie(recovery_login_headers)
        recovery_query = parse_qs(urlsplit(recovery_login_headers["location"]).query)
        fixture.expected_nonce = recovery_query["nonce"][0]
        fixture.expected_challenge = recovery_query["code_challenge"][0]
        fixture.identity_available = False
        identity_status, identity_headers, identity_body = request(
            f"/auth/callback?code={FIXTURE_CODE}&state={recovery_query['state'][0]}",
            cookie=f"__Host-oauth={recovery_binding}",
        )
        fixture.identity_available = True
        identity_cookies = set_cookies(identity_headers)
        if (
            identity_status != 503
            or json.loads(identity_body).get("code") != "identity_unavailable"
            or len(identity_cookies) != 1
        ):
            raise RuntimeError("packed BFF Identity outage did not fail without a session")
        assert_binding_clear(identity_cookies[0])

        final_login_status, final_login_headers, _final_login_body = request("/auth/login")
        if final_login_status != 307:
            raise RuntimeError("packed BFF recovery login failed")
        assert_headers(final_login_headers, allow_cookie=True)
        final_binding = oauth_binding_cookie(final_login_headers)
        final_query = parse_qs(urlsplit(final_login_headers["location"]).query)
        fixture.expected_nonce = final_query["nonce"][0]
        fixture.expected_challenge = final_query["code_challenge"][0]
        final_status, final_headers, _final_body = request(
            f"/auth/callback?code={FIXTURE_CODE}&state={final_query['state'][0]}",
            cookie=f"__Host-oauth={final_binding}",
        )
        final_cookies = set_cookies(final_headers)
        if final_status != 303 or len(final_cookies) != 2:
            raise RuntimeError("packed BFF did not recover after upstream outages")
        assert_binding_clear(
            next(
                (cookie for cookie in final_cookies if cookie.startswith('__Host-oauth="";')),
                "",
            )
        )

        run(*COMPOSE, "stop", "-t", "10", "redis")
        wait_for("/health/live", 200)
        wait_for("/health/ready", 503)
        redis_login_status, redis_login_headers, redis_login_body = request("/auth/login")
        if (
            redis_login_status != 503
            or json.loads(redis_login_body).get("code") != "transaction_store_unavailable"
            or "set-cookie" in redis_login_headers
        ):
            raise RuntimeError("packed BFF Redis outage did not prevent login/session state")
        run(*COMPOSE, "up", "-d", "--wait", "redis")
        wait_for("/health/ready", 200)

        image = json.loads(run("image", "inspect", "reference-bff:local"))[0]
        redis_image = json.loads(run("image", "inspect", "redis:8.2.1-alpine"))[0]
        redis_digests = redis_image.get("RepoDigests") or []
        if len(redis_digests) != 1 or not redis_digests[0].startswith("redis@sha256:"):
            raise RuntimeError("official Redis image lacks one immutable repository digest")
        started = time.monotonic()
        run("stop", "--timeout", "20", container_id)
        shutdown_seconds = time.monotonic() - started
        stopped = json.loads(run("inspect", container_id))[0]["State"]
        logs = run("logs", container_id, check=False)
        if stopped.get("ExitCode") != 0 or shutdown_seconds >= 20:
            raise RuntimeError("packed BFF did not shut down cleanly within the bound")
        if any(
            marker in logs.casefold()
            for marker in (
                "client_secret",
                "redis://",
                "code_verifier",
                "access_token",
                "id_token",
                "refresh_token",
                "synthetic-cognito-subject",
                "__host-oauth",
                "transaction_id",
            )
        ) or any(
            value and value in logs
            for value in (
                fixture.access_token,
                fixture.id_token,
                fixture.refresh_token,
                copied_binding,
                binding,
                denied_binding,
                outage_binding,
                recovery_binding,
                final_binding,
                copied_query["state"][0],
                copied_query["nonce"][0],
                query["state"][0],
                query["nonce"][0],
                denied_query["state"][0],
                outage_query["state"][0],
                recovery_query["state"][0],
                final_query["state"][0],
            )
        ):
            raise RuntimeError("packed BFF logs contain forbidden configuration material")
        print(
            "reference BFF packed image passed: "
            f"image={image['Id']} redis={redis_digests[0]} uid_gid=10002:10002 "
            "read_only=true cap_drop=ALL no_new_privileges=true dependency_isolation=true "
            "package_managers_absent=true "
            "callback_e2e=true browser_binding=true cross_browser_rejected=true "
            "binding_cleanup=true bootstrap_before_session=true replay_rejected=true "
            "server_side_token_custody=true browser_token_storage_absent=true "
            "provider_identity_redis_outages=true recovery=true no_cors=true "
            f"shutdown_seconds={shutdown_seconds:.3f}"
        )
        return 0
    finally:
        try:
            if compose_attempted:
                run(*COMPOSE, "down", "--volumes", "--remove-orphans", check=False)
        finally:
            try:
                if fixture_thread_started:
                    server.shutdown()
            finally:
                try:
                    server.server_close()
                    if fixture_thread_started and fixture_thread is not None:
                        fixture_thread.join(timeout=5)
                finally:
                    if previous_fixture_origin is None:
                        os.environ.pop(FIXTURE_ORIGIN_ENVIRONMENT, None)
                    else:
                        os.environ[FIXTURE_ORIGIN_ENVIRONMENT] = previous_fixture_origin


if __name__ == "__main__":
    raise SystemExit(main())
