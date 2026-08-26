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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
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
PROFILE_DOCUMENT = {
    "user_id": FIXTURE_USER_ID,
    "email": "synthetic@example.invalid",
    "email_verified": True,
    "display_name": None,
    "avatar_url": None,
    "version": 1,
    "created_at": "2026-08-25T00:00:00+00:00",
    "updated_at": "2026-08-25T00:00:00+00:00",
}


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
    refresh_rejected: bool = False
    identity_available: bool = True
    identity_rejected: bool = False
    refresh_delay_seconds: float = 0.0
    refresh_requests: int = 0
    token_family_id: str = field(default="synthetic-packed-token-family", repr=False)
    access_token: str = field(default="", repr=False)
    id_token: str = field(default="", repr=False)
    refresh_token: str = field(default="synthetic-packed-refresh-token", repr=False)
    issued_values: list[str] = field(default_factory=list, repr=False)
    issuer: str = field(default="", repr=False)
    events: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

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

    def issue_tokens(self, *, rotated: bool = False) -> None:
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
            "origin_jti": self.token_family_id,
        }
        self.access_token = jwt.encode(
            {
                **common,
                "aud": FIXTURE_RESOURCE,
                "client_id": FIXTURE_CLIENT_ID,
                "token_use": "access",  # nosec B105
                "scope": FIXTURE_SCOPES,
                "jti": f"synthetic-packed-access-{'rotated' if rotated else 'initial'}",
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
                "at_hash": at_hash,
                "jti": f"synthetic-packed-id-{'rotated' if rotated else 'initial'}",
                **({} if rotated else {"nonce": self.expected_nonce}),
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.key_id, "typ": "JWT"},
        )
        self.refresh_token = (
            f"synthetic-packed-rotated-refresh-token-{self.refresh_requests}"
            if rotated
            else "synthetic-packed-refresh-token"
        )
        self.issued_values.extend((self.access_token, self.id_token, self.refresh_token))


def fixture_handler(state: FixtureState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def _json(
            self,
            status: int,
            document: dict[str, Any],
            *,
            headers: dict[str, str] | None = None,
        ) -> None:
            body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/test-pool/.well-known/jwks.json":
                state.events.append("jwks")
                self._json(200, {"keys": [state.public_jwk()]})
                return
            if self.path == "/v1/me":
                state.events.append("profile")
                if state.identity_rejected:
                    self._json(401, {"error": "invalid_token"})
                    return
                if not state.identity_available:
                    self._json(503, {"error": "unavailable"})
                    return
                if (
                    self.headers.get("Authorization") != f"Bearer {state.access_token}"
                    or self.headers.get("Accept") != "application/json"
                    or self.headers.get("Cookie") is not None
                ):
                    self._json(401, {"error": "invalid_token"})
                    return
                self._json(
                    200,
                    PROFILE_DOCUMENT,
                    headers={"ETag": '"v1"'},
                )
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/oauth2/token":
                self._json(404, {"error": "not_found"})
                return
            if not state.token_available:
                state.events.append("token-unavailable")
                self._json(503, {"error": "temporarily_unavailable"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
            expected_basic = base64.b64encode(
                f"{FIXTURE_CLIENT_ID}:{FIXTURE_CLIENT_SECRET}".encode()
            ).decode()
            if self.headers.get("Authorization") != f"Basic {expected_basic}":
                self._json(401, {"error": "invalid_client"})
                return
            grant_type = form.get("grant_type")
            if grant_type == ["refresh_token"]:
                state.events.append("refresh")
                with state.lock:
                    state.refresh_requests += 1
                if state.refresh_rejected:
                    self._json(400, {"error": "invalid_grant"})
                    return
                expected_refresh = {
                    "grant_type": ["refresh_token"],
                    "client_id": [FIXTURE_CLIENT_ID],
                    "refresh_token": [state.refresh_token],
                }
                if form != expected_refresh:
                    self._json(400, {"error": "invalid_grant"})
                    return
                if state.refresh_delay_seconds:
                    time.sleep(state.refresh_delay_seconds)
                state.issue_tokens(rotated=True)
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
                return
            state.events.append("token")
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
            if form != expected or challenge != state.expected_challenge:
                self._json(400, {"error": "invalid_grant"})
                return
            state.issue_tokens(rotated=False)
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


def session_cookie(headers: dict[str, str], *, expected_session_id: str | None = None) -> str:
    cookies = set_cookies(headers)
    if len(cookies) != 1:
        raise RuntimeError("packed BFF session renewal cookie count differs")
    match = re.fullmatch(
        r"__Host-session=([A-Za-z0-9_-]{43}); HttpOnly; Max-Age=([0-9]+); "
        r"Path=/; SameSite=lax; Secure",
        cookies[0],
    )
    if (
        match is None
        or not 0 < int(match.group(2)) <= 43_200
        or (expected_session_id is not None and match.group(1) != expected_session_id)
        or "Domain=" in cookies[0]
    ):
        raise RuntimeError("packed BFF session renewal cookie differs")
    return match.group(1)


def assert_session_clear(headers: dict[str, str]) -> None:
    cookies = set_cookies(headers)
    if len(cookies) != 1 or (
        re.fullmatch(
            r'__Host-session=""; expires=[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} '
            r"[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT; HttpOnly; "
            r"Max-Age=0; Path=/; SameSite=lax; Secure",
            cookies[0],
        )
        is None
    ):
        raise RuntimeError("packed BFF session clearing cookie differs")


def redis_session(key: str) -> dict[str, Any]:
    raw = run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "--raw", "GET", key)
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise RuntimeError("packed BFF session is not an object")
    return document


def replace_redis_session(key: str, document: dict[str, Any], ttl: int) -> None:
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True)
    if (
        run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "SET", key, encoded, "EX", str(ttl))
        != "OK"
    ):
        raise RuntimeError("packed BFF fixture could not replace the bounded session")


def stale_redis_cas(
    key: str, expected: dict[str, Any], replacement: dict[str, Any], ttl: int
) -> int:
    script = (
        "local c=redis.call('GET',KEYS[1]);"
        "if not c then return 0 end;"
        "if c~=ARGV[1] then return -1 end;"
        "local s=redis.call('SET',KEYS[1],ARGV[2],'EX',ARGV[3],'XX');"
        "if not s then return 0 end;return 1"
    )
    output = run(
        *COMPOSE,
        "exec",
        "-T",
        "redis",
        "redis-cli",
        "--raw",
        "EVAL",
        script,
        "1",
        key,
        json.dumps(expected, separators=(",", ":"), sort_keys=True),
        json.dumps(replacement, separators=(",", ":"), sort_keys=True),
        str(ttl),
    )
    return int(output)


def concurrent_profile_reads(
    session_id: str, *, count: int = 50
) -> list[tuple[int, dict[str, str], bytes]]:
    barrier = threading.Barrier(count)

    def read() -> tuple[int, dict[str, str], bytes]:
        barrier.wait(timeout=5)
        return request("/api/me", cookie=f"__Host-session={session_id}")

    with ThreadPoolExecutor(max_workers=count) as executor:
        return list(executor.map(lambda _index: read(), range(count)))


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


def expand_fixture_backlog(server: ThreadingHTTPServer) -> None:
    fixture_socket = getattr(server, "socket", None)
    if fixture_socket is not None:
        fixture_socket.listen(128)


def main() -> int:
    fixture = FixtureState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), fixture_handler(fixture))
    expand_fixture_backlog(server)
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
        missing_status, missing_headers, missing_body = request("/api/me")
        if missing_status != 401 or json.loads(missing_body).get("code") != "session_required":
            raise RuntimeError("packed BFF accepted a profile read without a session")
        assert_headers(missing_headers, allow_cookie=True)
        assert_session_clear(missing_headers)
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
            "nonce": fixture.expected_nonce,
            "token_family_id": fixture.token_family_id,
            "access_token": fixture.access_token,
            "id_token": fixture.id_token,
            "refresh_token": fixture.refresh_token,
            "refresh_version": 0,
            "version": 2,
        }
        if any(stored_session.get(key) != value for key, value in expected_record_values.items()):
            raise RuntimeError("packed BFF server-side session record differs")
        session_ttl = int(run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "TTL", session_key))
        if not 0 < session_ttl <= 43_200:
            raise RuntimeError("packed BFF session TTL exceeds the idle bound")

        stale_record = dict(stored_session)
        original_created_at = stored_session["created_at"]
        original_absolute_expires_at = stored_session["absolute_expires_at"]
        stored_session["access_expires_at"] = int(time.time()) + 120
        replace_redis_session(session_key, stored_session, session_ttl)
        fixture.refresh_delay_seconds = 0.1
        profile_results = concurrent_profile_reads(session_id)
        fixture.refresh_delay_seconds = 0.0
        if len(profile_results) != 50 or fixture.refresh_requests != 1:
            raise RuntimeError("packed BFF refresh single flight request count differs")
        for profile_status, profile_headers, profile_body in profile_results:
            if (
                profile_status != 200
                or json.loads(profile_body) != PROFILE_DOCUMENT
                or profile_headers.get("etag") != '"v1"'
            ):
                summary = Counter(
                    (
                        status,
                        json.loads(body).get("code"),
                        headers.get("etag"),
                        len(set_cookies(headers)),
                    )
                    for status, headers, body in profile_results
                )
                raise RuntimeError(f"packed BFF concurrent profile result differs: {summary}")
            assert_headers(profile_headers, allow_cookie=True)
            session_cookie(profile_headers, expected_session_id=session_id)
        refreshed_session = redis_session(session_key)
        if (
            refreshed_session.get("refresh_version") != 1
            or refreshed_session.get("refresh_token") != fixture.refresh_token
            or refreshed_session.get("access_token") != fixture.access_token
            or refreshed_session.get("id_token") != fixture.id_token
            or refreshed_session.get("created_at") != original_created_at
            or refreshed_session.get("absolute_expires_at") != original_absolute_expires_at
            or refreshed_session.get("token_family_id") != fixture.token_family_id
            or refreshed_session.get("nonce") != fixture.expected_nonce
        ):
            raise RuntimeError("packed BFF rotated session differs")
        refreshed_ttl = int(run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "TTL", session_key))
        if not 0 < refreshed_ttl <= 43_200:
            raise RuntimeError("packed BFF refreshed session TTL differs")
        if stale_redis_cas(session_key, stale_record, stale_record, refreshed_ttl) != -1:
            raise RuntimeError("packed BFF accepted a stale session overwrite")
        if redis_session(session_key) != refreshed_session:
            raise RuntimeError("packed BFF stale CAS changed the refreshed session")
        refresh_lock_digest = hashlib.sha256(
            f"reference-bff:local:compose\x00refresh-lock\x00{session_id}\x000".encode()
        ).hexdigest()
        refresh_lock_key = f"reference-bff:local:compose:refresh-lock:{refresh_lock_digest}"
        if (
            run(
                *COMPOSE,
                "exec",
                "-T",
                "redis",
                "redis-cli",
                "EXISTS",
                refresh_lock_key,
            )
            != "0"
        ):
            raise RuntimeError("packed BFF left a refresh lock")

        fixture.identity_available = False
        profile_outage_status, profile_outage_headers, profile_outage_body = request(
            "/api/me", cookie=f"__Host-session={session_id}"
        )
        fixture.identity_available = True
        if (
            profile_outage_status != 503
            or json.loads(profile_outage_body).get("code") != "identity_unavailable"
            or "set-cookie" in profile_outage_headers
            or run(
                *COMPOSE,
                "exec",
                "-T",
                "redis",
                "redis-cli",
                "EXISTS",
                session_key,
            )
            != "1"
        ):
            raise RuntimeError("packed BFF Identity outage did not preserve the session")
        assert_headers(profile_outage_headers)
        fixture.identity_rejected = True
        rejected_status, rejected_headers, rejected_body = request(
            "/api/me", cookie=f"__Host-session={session_id}"
        )
        fixture.identity_rejected = False
        if rejected_status != 401 or json.loads(rejected_body).get("code") != "session_required":
            raise RuntimeError("packed BFF Identity rejection did not invalidate the session")
        assert_headers(rejected_headers, allow_cookie=True)
        assert_session_clear(rejected_headers)
        if run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "EXISTS", session_key) != "0":
            raise RuntimeError("packed BFF retained an Identity-rejected session")
        if stale_redis_cas(session_key, refreshed_session, refreshed_session, refreshed_ttl) != 0:
            raise RuntimeError("packed BFF recreated a deleted session")

        events_before_replay = list(fixture.events)
        replay_status, replay_headers, replay_body = request(
            callback_path, cookie=f"__Host-oauth={binding}"
        )
        if (
            replay_status != 400
            or json.loads(replay_body).get("code") != "invalid_oauth_transaction"
            or "set-cookie" in replay_headers
            or fixture.events != events_before_replay
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
        final_session_cookie = next(
            (cookie for cookie in final_cookies if cookie.startswith("__Host-session=")),
            "",
        )
        final_session_match = re.fullmatch(
            r"__Host-session=([A-Za-z0-9_-]{43}); HttpOnly; Max-Age=([0-9]+); "
            r"Path=/; SameSite=lax; Secure",
            final_session_cookie,
        )
        if final_session_match is None:
            raise RuntimeError("packed BFF recovery session cookie differs")
        final_session_id = final_session_match.group(1)
        final_session_digest = hashlib.sha256(
            f"reference-bff:local:compose\x00session\x00{final_session_id}".encode()
        ).hexdigest()
        final_session_key = f"reference-bff:local:compose:session:{final_session_digest}"
        final_record = redis_session(final_session_key)
        final_ttl = int(run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "TTL", final_session_key))
        final_record["access_expires_at"] = int(time.time()) + 120
        replace_redis_session(final_session_key, final_record, final_ttl)
        fixture.token_available = False
        fallback_status, fallback_headers, fallback_body = request(
            "/api/me", cookie=f"__Host-session={final_session_id}"
        )
        if (
            fallback_status != 200
            or json.loads(fallback_body) != PROFILE_DOCUMENT
            or redis_session(final_session_key).get("refresh_version") != 0
        ):
            raise RuntimeError("packed BFF did not use one still-valid access-token fallback")
        assert_headers(fallback_headers, allow_cookie=True)
        session_cookie(fallback_headers, expected_session_id=final_session_id)
        final_record = redis_session(final_session_key)
        deadline = time.monotonic() + 2
        while int(time.time()) <= int(final_record["created_at"]):
            if time.monotonic() >= deadline:
                raise RuntimeError("packed BFF clock did not advance for the expiry fixture")
            time.sleep(0.05)
        final_record["access_expires_at"] = int(time.time())
        final_ttl = int(run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "TTL", final_session_key))
        replace_redis_session(final_session_key, final_record, final_ttl)
        expired_outage_status, expired_outage_headers, expired_outage_body = request(
            "/api/me", cookie=f"__Host-session={final_session_id}"
        )
        fixture.token_available = True
        if (
            expired_outage_status != 503
            or json.loads(expired_outage_body).get("code") != "session_unavailable"
            or "set-cookie" in expired_outage_headers
            or run(
                *COMPOSE,
                "exec",
                "-T",
                "redis",
                "redis-cli",
                "EXISTS",
                final_session_key,
            )
            != "1"
        ):
            raise RuntimeError("packed BFF expired-token outage did not preserve the session")
        assert_headers(expired_outage_headers)
        refreshed_status, refreshed_headers, refreshed_body = request(
            "/api/me", cookie=f"__Host-session={final_session_id}"
        )
        if (
            refreshed_status != 200
            or json.loads(refreshed_body) != PROFILE_DOCUMENT
            or redis_session(final_session_key).get("refresh_version") != 1
        ):
            raise RuntimeError("packed BFF did not recover the expired session through refresh")
        assert_headers(refreshed_headers, allow_cookie=True)
        session_cookie(refreshed_headers, expected_session_id=final_session_id)

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
        redis_profile_status, redis_profile_headers, redis_profile_body = request(
            "/api/me", cookie=f"__Host-session={final_session_id}"
        )
        if (
            redis_profile_status != 503
            or json.loads(redis_profile_body).get("code") != "session_unavailable"
            or "set-cookie" in redis_profile_headers
        ):
            raise RuntimeError("packed BFF Redis outage cleared or accepted a valid session")
        assert_headers(redis_profile_headers)
        run(*COMPOSE, "up", "-d", "--wait", "redis")
        wait_for("/health/ready", 200)
        lost_status, lost_headers, lost_body = request(
            "/api/me", cookie=f"__Host-session={final_session_id}"
        )
        if lost_status != 401 or json.loads(lost_body).get("code") != "session_required":
            raise RuntimeError("packed BFF did not require login after volatile Redis loss")
        assert_headers(lost_headers, allow_cookie=True)
        assert_session_clear(lost_headers)

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
                "__host-session",
                "transaction_id",
                "token-family",
                "refresh-lock",
            )
        ) or any(
            value and value in logs
            for value in (
                *fixture.issued_values,
                session_id,
                final_session_id,
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
            "profile_read=true strict_etag=true stable_session_id=true "
            "refresh_single_flight_50=true refresh_version_once=true rotated_refresh=true "
            "stale_cas_rejected=true no_resurrection=true no_lock_residue=true "
            "valid_token_fallback=true expired_token_outage=true exact_invalidation=true "
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
