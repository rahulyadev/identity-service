"""Exercise the packed reference BFF with disposable Redis and hardened runtime controls."""

from __future__ import annotations

import base64
import hashlib
import http.client
import inspect
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
from urllib.parse import parse_qs, quote, unquote, urlsplit

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


def container_inventory(root: str = "/", owner_uid: int = 0) -> dict[str, Any]:
    """Read authentic DPKG data without package-manager executables.

    This self-contained function is also the code executed inside both packed images.
    The alternate root/owner are solely for executable synthetic regression fixtures.
    DPKG MD5 values reconcile files to package records, not cryptographic image trust.
    """
    import hashlib
    import platform
    import re
    import stat
    from pathlib import Path

    def require(condition: bool, code: str) -> None:
        if not condition:
            raise RuntimeError("container inventory failed: " + code)

    base = Path(root).resolve(strict=True)

    def controlled(path: Path, directory: bool = False) -> None:
        info = path.lstat()
        require(
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == owner_uid
            and info.st_gid == owner_uid
            and not info.st_mode & 0o022,
            "metadata-control",
        )
        if not directory:
            require(0 < info.st_size <= 8 * 1024 * 1024, "metadata-size")

    def data(path: Path) -> str:
        controlled(path)
        text = path.read_bytes().decode("utf-8")
        require("\x00" not in text and "\r" not in text and text.endswith("\n"), "metadata-framing")
        return text

    database = base / "var/lib/dpkg"
    for name in ("var", "var/lib", "var/lib/dpkg", "var/lib/dpkg/info"):
        controlled(base / name, directory=True)
    status = data(database / "status")
    require(status.endswith("\n\n"), "status-truncated")
    packages: list[dict[str, Any]] = []
    keys: set[tuple[str, str]] = set()
    expected_lists: set[str] = set()
    core = {
        "libc6",
        "libssl3",
        "libgnutls30",
        "libbz2-1.0",
        "libffi8",
        "liblzma5",
        "libsqlite3-0",
        "libuuid1",
        "zlib1g",
        "libstdc++6",
        "libgcc-s1",
        "libcrypt1",
    }
    for paragraph in status.removesuffix("\n\n").split("\n\n"):
        fields: dict[str, str] = {}
        previous = ""
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                require(bool(previous), "orphan-continuation")
                fields[previous] += "\n" + line
                continue
            match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*): ?(.*)", line)
            require(match is not None, "status-field")
            if match is None:
                raise RuntimeError("container inventory failed: status-field")
            previous, value = match.groups()
            require(
                previous.casefold() not in {key.casefold() for key in fields}, "duplicate-field"
            )
            fields[previous] = value
        require(
            {"Package", "Version", "Architecture", "Status"} <= fields.keys(),
            "status-required-fields",
        )
        name, version, arch = (fields[key] for key in ("Package", "Version", "Architecture"))
        require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name) is not None, "package-name")
        require(re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", version) is not None, "package-version")
        require(arch in {"all", "amd64", "arm64"}, "package-architecture")
        require(fields["Status"] == "install ok installed", "package-state")
        require((name, arch) not in keys, "duplicate-package")
        keys.add((name, arch))
        choices = [database / "info" / (stem + ".list") for stem in (name, name + ":" + arch)]
        lists = [path for path in choices if path.exists() or path.is_symlink()]
        require(len(lists) == 1, "ownership-list")
        ownership = lists[0]
        expected_lists.add(ownership.name)
        paths = data(ownership).splitlines()
        require(
            all(path.startswith("/") and ".." not in Path(path).parts for path in paths)
            and len(paths) == len(set(paths)),
            "ownership-path",
        )
        libraries: list[dict[str, str]] = []
        if name in core:
            checksums: dict[str, str] = {}
            for line in data(ownership.with_suffix(".md5sums")).splitlines():
                match = re.fullmatch(r"([a-f0-9]{32})  (.+)", line)
                require(match is not None, "file-checksum-record")
                if match is None:
                    raise RuntimeError("container inventory failed: file-checksum-record")
                digest, relative = match.groups()
                require(relative not in checksums, "duplicate-file-checksum")
                checksums[relative] = digest
            for installed in paths:
                if re.search(r"\.so(?:\.[0-9]+)*$", Path(installed).name) is None:
                    continue
                path = base / installed.lstrip("/")
                require(path.exists(), "retained-library-missing")
                resolved = path.resolve(strict=True)
                require(resolved.is_relative_to(base), "library-path-escape")
                if path.is_symlink():
                    continue
                controlled(path)
                contents = path.read_bytes()
                require(contents.startswith(b"\x7fELF"), "library-format")
                expected = checksums.get(installed.lstrip("/"))
                require(
                    expected is not None
                    and hashlib.md5(contents, usedforsecurity=False).hexdigest() == expected,
                    "library-checksum",
                )
                libraries.append(
                    {"path": installed, "sha256": hashlib.sha256(contents).hexdigest()}
                )
            require(bool(libraries), "core-library-coverage")
        packages.append(
            {
                "name": name,
                "version": version,
                "architecture": arch,
                "source": fields.get("Source", name),
                "libraries": libraries,
            }
        )
    require(core <= {package["name"] for package in packages}, "core-package-coverage")
    require(
        {path.name for path in (database / "info").glob("*.list")} == expected_lists,
        "orphan-package-ownership",
    )
    return {
        "status_sha256": hashlib.sha256(status.encode()).hexdigest(),
        "status_bytes": len(status.encode()),
        "owner_uid": owner_uid,
        "python": platform.python_version(),
        "machine": platform.machine(),
        "packages": sorted(
            packages, key=lambda package: (package["name"], package["architecture"])
        ),
    }


def inventory_probe_source(root: str = "/", owner_uid: int = 0) -> str:
    """Emit the actual fixed, shell-free packed probe (fixture arguments are test-only)."""
    return (
        "import json\nfrom typing import Any\n"
        + inspect.getsource(container_inventory)
        + f"\nprint(json.dumps(container_inventory({root!r}, {owner_uid!r}),sort_keys=True))\n"
    )


def verify_inventory_sbom(inventory: dict[str, Any], sbom: dict[str, Any]) -> None:
    """Require identity/version/architecture equality, not merely a nonzero OS count."""
    expected = {
        (package["name"], package["version"], package["architecture"])
        for package in inventory["packages"]
    }
    actual: list[tuple[str, str, str]] = []
    for package in sbom.get("packages", []):
        for reference in package.get("externalRefs", []):
            locator = reference.get("referenceLocator", "")
            if reference.get("referenceType") != "purl" or not locator.startswith("pkg:deb/"):
                continue
            parsed = urlsplit(locator)
            name_version = parsed.path.removeprefix("deb/debian/").split("@")
            qualifiers = parse_qs(parsed.query, strict_parsing=True)
            if (
                not parsed.path.startswith("deb/debian/")
                or len(name_version) != 2
                or set(qualifiers.get("arch", [])) not in ({"all"}, {"amd64"}, {"arm64"})
            ):
                raise RuntimeError("container SBOM failed: package-identity")
            name, version = (unquote(value) for value in name_version)
            if name != package.get("name") or version != package.get("versionInfo"):
                raise RuntimeError("container SBOM failed: package-version")
            actual.append((name, version, qualifiers["arch"][0]))
    if (
        sbom.get("spdxVersion") != "SPDX-2.3"
        or not expected
        or len(actual) != len(set(actual))
        or set(actual) != expected
    ):
        raise RuntimeError("container SBOM failed: OS-catalog-coverage")


def verify_packed_inventory() -> dict[str, Any]:
    """Run the inventory gate as the configured non-root BFF user."""
    inventory: dict[str, Any] = json.loads(
        run(*COMPOSE, "exec", "-T", "bff", "python", "-c", inventory_probe_source())
    )
    if inventory["python"] != "3.14.7" or inventory["owner_uid"] != 0:
        raise RuntimeError("packed BFF inventory/runtime differs")
    return inventory


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
    revoke_available: bool = True
    revoke_requests: int = 0
    revoke_successes: int = 0
    profile_version: int = 1
    profile_display_name: str | None = None
    patch_requests: int = 0
    patch_successes: int = 0
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
            if self.path == "/oauth2/revoke":
                state.events.append("revoke")
                with state.lock:
                    state.revoke_requests += 1
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
                expected_basic = base64.b64encode(
                    f"{FIXTURE_CLIENT_ID}:{FIXTURE_CLIENT_SECRET}".encode()
                ).decode()
                if (
                    self.headers.get("Authorization") != f"Basic {expected_basic}"
                    or self.headers.get("Content-Type") != "application/x-www-form-urlencoded"
                    or form != {"token": [state.refresh_token]}
                    or self.headers.get("Cookie") is not None
                ):
                    self._json(401, {"error": "invalid_client"})
                    return
                if not state.revoke_available:
                    self._json(503, {"error": "temporarily_unavailable"})
                    return
                with state.lock:
                    state.revoke_successes += 1
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
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

        def do_PATCH(self) -> None:
            if self.path != "/v1/me":
                self._json(404, {"error": "not_found"})
                return
            state.events.append("profile-patch")
            if state.identity_rejected:
                self._json(401, {"error": "invalid_token"})
                return
            if not state.identity_available:
                self._json(503, {"error": "unavailable"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if (
                self.headers.get("Authorization") != f"Bearer {state.access_token}"
                or self.headers.get("Accept") != "application/json"
                or self.headers.get("Content-Type") != "application/merge-patch+json"
                or any(
                    self.headers.get(name) is not None
                    for name in (
                        "Cookie",
                        "Origin",
                        "Sec-Fetch-Site",
                        "X-CSRF-Token",
                        "X-Request-ID",
                    )
                )
                or body not in {b'{"display_name":"Packed"}', b'{"display_name":null}'}
            ):
                self._json(400, {"error": "invalid_request"})
                return
            with state.lock:
                state.patch_requests += 1
                if self.headers.get("If-Match") != f'"v{state.profile_version}"':
                    self._json(412, {"error": "stale"})
                    return
                state.profile_display_name = (
                    "Packed" if body == b'{"display_name":"Packed"}' else None
                )
                state.profile_version += 1
                state.patch_successes += 1
                version = state.profile_version
                display_name = state.profile_display_name
            document = dict(PROFILE_DOCUMENT)
            document["display_name"] = display_name
            document["version"] = version
            self._json(200, document, headers={"ETag": f'"v{version}"'})

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


def request(
    path: str,
    *,
    cookie: str | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", 8081, timeout=3)
    try:
        request_headers = {"Host": "localhost", "Connection": "close"}
        if cookie is not None:
            request_headers["Cookie"] = cookie
        request_headers.update(headers or {})
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        body = response.read(16_385)
        headers: dict[str, str] = {}
        cookies: list[str] = []
        for name, value in response.getheaders():
            normalized = name.casefold()
            if normalized == "set-cookie":
                cookies.append(value)
            else:
                headers[normalized] = (
                    value if normalized not in headers else headers[normalized] + "\n" + value
                )
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


def assert_bff_clear(headers: dict[str, str]) -> None:
    cookies = set_cookies(headers)
    if len(cookies) != 2:
        raise RuntimeError("packed BFF cookie clearing count differs")
    oauth = next((cookie for cookie in cookies if cookie.startswith('__Host-oauth="";')), "")
    session = next(
        (cookie for cookie in cookies if cookie.startswith('__Host-session="";')),
        "",
    )
    assert_binding_clear(oauth)
    assert_session_clear({"set-cookie": session})


def assert_logout_redirect(headers: dict[str, str], fixture_origin: str) -> None:
    target = urlsplit(headers.get("location", ""))
    query = parse_qs(target.query, strict_parsing=True)
    if (
        f"{target.scheme}://{target.netloc}{target.path}" != f"{fixture_origin}/logout"
        or query
        != {
            "client_id": [FIXTURE_CLIENT_ID],
            "logout_uri": ["http://localhost:8081/auth/signed-out"],
        }
        or set(query) != {"client_id", "logout_uri"}
    ):
        raise RuntimeError("packed BFF logout redirect differs")


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


def concurrent_profile_patches(
    session_id: str,
    csrf_token: str,
    *,
    count: int = 20,
) -> list[tuple[int, dict[str, str], bytes]]:
    barrier = threading.Barrier(count)
    body = b'{"display_name":"  Packed  "}'

    def patch() -> tuple[int, dict[str, str], bytes]:
        barrier.wait(timeout=5)
        return request(
            "/api/me",
            cookie=f"__Host-session={session_id}",
            method="PATCH",
            headers={
                "Origin": "http://localhost:8081",
                "X-CSRF-Token": csrf_token,
                "Sec-Fetch-Site": "same-origin",
                "If-Match": '"v1"',
                "Content-Type": "application/merge-patch+json",
            },
            body=body,
        )

    with ThreadPoolExecutor(max_workers=count) as executor:
        return list(executor.map(lambda _index: patch(), range(count)))


def concurrent_logouts(
    session_id: str,
    csrf_token: str,
    *,
    count: int = 50,
) -> list[tuple[int, dict[str, str], bytes]]:
    barrier = threading.Barrier(count)

    def logout() -> tuple[int, dict[str, str], bytes]:
        barrier.wait(timeout=5)
        return request(
            "/auth/logout",
            cookie=f"__Host-session={session_id}",
            method="POST",
            headers={
                "Origin": "http://localhost:8081",
                "X-CSRF-Token": csrf_token,
                "Sec-Fetch-Site": "same-origin",
            },
        )

    with ThreadPoolExecutor(max_workers=count) as executor:
        return list(executor.map(lambda _index: logout(), range(count)))


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
        verify_packed_inventory()

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
            "version": 3,
        }
        if any(stored_session.get(key) != value for key, value in expected_record_values.items()):
            raise RuntimeError("packed BFF server-side session record differs")
        csrf_token = stored_session.get("csrf_token")
        if (
            not isinstance(csrf_token, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]", csrf_token) is None
            or csrf_token
            in {
                session_id,
                fixture.expected_nonce,
                fixture.token_family_id,
                binding,
                copied_binding,
                query["state"][0],
            }
        ):
            raise RuntimeError("packed BFF CSRF session binding differs")
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
                or profile_headers.get("x-csrf-token") != csrf_token
                or csrf_token.encode() in profile_body
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

        session_before_denials = redis_session(session_key)
        patch_body = b'{"display_name":"  Packed  "}'
        denial_requests = (
            {
                "Origin": "http://localhost:8081",
                "X-CSRF-Token": "Q" * 43 if csrf_token != "Q" * 43 else "E" * 43,
                "Sec-Fetch-Site": "same-origin",
            },
            {
                "Origin": "http://attacker.invalid",
                "X-CSRF-Token": csrf_token,
                "Sec-Fetch-Site": "cross-site",
            },
        )
        for denial_headers in denial_requests:
            events_before_denial = list(fixture.events)
            denial_status, denial_response_headers, denial_body = request(
                "/api/me",
                cookie=f"__Host-session={session_id}",
                method="PATCH",
                headers={
                    **denial_headers,
                    "If-Match": '"v1"',
                    "Content-Type": "application/merge-patch+json",
                },
                body=patch_body,
            )
            if (
                denial_status != 403
                or json.loads(denial_body).get("code") != "csrf_failed"
                or "x-csrf-token" in denial_response_headers
                or "set-cookie" in denial_response_headers
                or csrf_token.encode() in denial_body
                or fixture.events != events_before_denial
                or redis_session(session_key) != session_before_denials
            ):
                raise RuntimeError("packed BFF CSRF denial crossed the no-mutation boundary")
            assert_headers(denial_response_headers)

        patch_results = concurrent_profile_patches(session_id, csrf_token)
        patch_successes = [result for result in patch_results if result[0] == 200]
        patch_conflicts = [result for result in patch_results if result[0] == 412]
        if len(patch_successes) != 1 or len(patch_conflicts) != 19:
            summary = Counter(
                (status, json.loads(body).get("code")) for status, _headers, body in patch_results
            )
            raise RuntimeError(f"packed BFF concurrent profile patch result differs: {summary}")
        success_status, success_headers, success_body = patch_successes[0]
        success_document = json.loads(success_body)
        if (
            success_status != 200
            or success_document.get("display_name") != "Packed"
            or success_document.get("version") != 2
            or success_headers.get("etag") != '"v2"'
            or success_headers.get("x-csrf-token") != csrf_token
            or csrf_token.encode() in success_body
        ):
            raise RuntimeError("packed BFF successful profile patch contract differs")
        assert_headers(success_headers, allow_cookie=True)
        session_cookie(success_headers, expected_session_id=session_id)
        for conflict_status, conflict_headers, conflict_body in patch_conflicts:
            if (
                conflict_status != 412
                or json.loads(conflict_body).get("code") != "profile_conflict"
                or "x-csrf-token" in conflict_headers
                or "set-cookie" in conflict_headers
                or csrf_token.encode() in conflict_body
            ):
                raise RuntimeError("packed BFF profile conflict contract differs")
            assert_headers(conflict_headers)
        if fixture.patch_requests != 20 or fixture.patch_successes != 1:
            raise RuntimeError("packed Identity profile concurrency differs")
        session_after_patches = redis_session(session_key)
        if (
            session_after_patches.get("csrf_token") != csrf_token
            or session_after_patches.get("refresh_version") != 1
            or session_after_patches.get("refresh_token") != fixture.refresh_token
        ):
            raise RuntimeError("packed profile patch lost the session CSRF binding")
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
            raise RuntimeError("packed profile patch left refresh/CAS residue")

        fixture.identity_available = False
        patch_outage_status, patch_outage_headers, patch_outage_body = request(
            "/api/me",
            cookie=f"__Host-session={session_id}",
            method="PATCH",
            headers={
                "Origin": "http://localhost:8081",
                "X-CSRF-Token": csrf_token,
                "Sec-Fetch-Site": "same-origin",
                "If-Match": '"v2"',
                "Content-Type": "application/merge-patch+json",
            },
            body=b'{"display_name":null}',
        )
        fixture.identity_available = True
        if (
            patch_outage_status != 503
            or json.loads(patch_outage_body).get("code") != "identity_unavailable"
            or "x-csrf-token" in patch_outage_headers
            or "set-cookie" in patch_outage_headers
            or csrf_token.encode() in patch_outage_body
        ):
            raise RuntimeError("packed profile patch outage boundary differs")
        assert_headers(patch_outage_headers)
        clear_status, clear_headers, clear_body = request(
            "/api/me",
            cookie=f"__Host-session={session_id}",
            method="PATCH",
            headers={
                "Origin": "http://localhost:8081",
                "X-CSRF-Token": csrf_token,
                "Sec-Fetch-Site": "same-origin",
                "If-Match": '"v2"',
                "Content-Type": "application/merge-patch+json",
            },
            body=b'{"display_name":null}',
        )
        if (
            clear_status != 200
            or json.loads(clear_body).get("display_name") is not None
            or json.loads(clear_body).get("version") != 3
            or clear_headers.get("etag") != '"v3"'
            or clear_headers.get("x-csrf-token") != csrf_token
            or csrf_token.encode() in clear_body
            or fixture.patch_requests != 21
            or fixture.patch_successes != 2
        ):
            raise RuntimeError("packed BFF recovered clear-profile patch differs")
        assert_headers(clear_headers, allow_cookie=True)
        session_cookie(clear_headers, expected_session_id=session_id)
        if redis_session(session_key).get("csrf_token") != csrf_token:
            raise RuntimeError("packed BFF clear-profile patch changed the CSRF binding")

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

        race_record = redis_session(final_session_key)
        race_csrf = race_record.get("csrf_token")
        if not isinstance(race_csrf, str):
            raise RuntimeError("packed BFF race session omitted its CSRF binding")
        race_record["access_expires_at"] = int(time.time()) + 120
        race_ttl = int(run(*COMPOSE, "exec", "-T", "redis", "redis-cli", "TTL", final_session_key))
        replace_redis_session(final_session_key, race_record, race_ttl)
        refresh_before_race = fixture.refresh_requests
        revoke_before_race = fixture.revoke_requests
        revoke_success_before_race = fixture.revoke_successes
        fixture.refresh_delay_seconds = 0.5
        fixture.revoke_available = False
        with ThreadPoolExecutor(max_workers=1) as executor:
            inflight_profile = executor.submit(
                request,
                "/api/me",
                cookie=f"__Host-session={final_session_id}",
            )
            race_deadline = time.monotonic() + 3
            while fixture.refresh_requests == refresh_before_race:
                if time.monotonic() >= race_deadline:
                    raise RuntimeError("packed BFF refresh/logout race did not reach refresh")
                time.sleep(0.01)
            race_logout_status, race_logout_headers, race_logout_body = request(
                "/auth/logout",
                cookie=f"__Host-session={final_session_id}",
                method="POST",
                headers={
                    "Origin": "http://localhost:8081",
                    "X-CSRF-Token": race_csrf,
                    "Sec-Fetch-Site": "same-origin",
                },
            )
            race_profile_status, race_profile_headers, race_profile_body = inflight_profile.result(
                timeout=5
            )
        fixture.refresh_delay_seconds = 0.0
        if (
            race_logout_status != 303
            or race_logout_body
            or fixture.revoke_requests != revoke_before_race + 1
            or fixture.revoke_successes != revoke_success_before_race
            or race_profile_status != 401
            or json.loads(race_profile_body).get("code") != "session_required"
            or run(
                *COMPOSE,
                "exec",
                "-T",
                "redis",
                "redis-cli",
                "EXISTS",
                final_session_key,
            )
            != "0"
        ):
            raise RuntimeError("packed BFF refresh/logout race resurrected or misreported state")
        assert_headers(race_logout_headers, allow_cookie=True)
        assert_logout_redirect(race_logout_headers, fixture_origin)
        assert_bff_clear(race_logout_headers)
        assert_headers(race_profile_headers, allow_cookie=True)
        assert_session_clear(race_profile_headers)
        if stale_redis_cas(final_session_key, race_record, race_record, race_ttl) != 0:
            raise RuntimeError("packed BFF stale refresh CAS recreated a logged-out session")

        logout_login_status, logout_login_headers, _logout_login_body = request("/auth/login")
        if logout_login_status != 307:
            raise RuntimeError("packed BFF logout-concurrency setup failed")
        assert_headers(logout_login_headers, allow_cookie=True)
        logout_binding = oauth_binding_cookie(logout_login_headers)
        logout_query = parse_qs(urlsplit(logout_login_headers["location"]).query)
        fixture.expected_nonce = logout_query["nonce"][0]
        fixture.expected_challenge = logout_query["code_challenge"][0]
        logout_callback_status, logout_callback_headers, _logout_callback_body = request(
            f"/auth/callback?code={FIXTURE_CODE}&state={logout_query['state'][0]}",
            cookie=f"__Host-oauth={logout_binding}",
        )
        logout_callback_cookies = set_cookies(logout_callback_headers)
        if logout_callback_status != 303 or len(logout_callback_cookies) != 2:
            raise RuntimeError("packed BFF logout-concurrency session setup failed")
        logout_session_cookie = next(
            (cookie for cookie in logout_callback_cookies if cookie.startswith("__Host-session=")),
            "",
        )
        logout_session_match = re.fullmatch(
            r"__Host-session=([A-Za-z0-9_-]{43}); HttpOnly; Max-Age=([0-9]+); "
            r"Path=/; SameSite=lax; Secure",
            logout_session_cookie,
        )
        if logout_session_match is None:
            raise RuntimeError("packed BFF logout-concurrency cookie differs")
        logout_session_id = logout_session_match.group(1)
        logout_session_digest = hashlib.sha256(
            f"reference-bff:local:compose\x00session\x00{logout_session_id}".encode()
        ).hexdigest()
        logout_session_key = f"reference-bff:local:compose:session:{logout_session_digest}"
        logout_record = redis_session(logout_session_key)
        logout_csrf = logout_record.get("csrf_token")
        if not isinstance(logout_csrf, str) or logout_csrf == race_csrf:
            raise RuntimeError("packed BFF independent logout session binding differs")

        cross_events = list(fixture.events)
        cross_session_status, cross_session_headers, cross_session_body = request(
            "/auth/logout",
            cookie=f"__Host-session={logout_session_id}",
            method="POST",
            headers={
                "Origin": "http://localhost:8081",
                "X-CSRF-Token": race_csrf,
                "Sec-Fetch-Site": "same-origin",
            },
        )
        if (
            cross_session_status != 403
            or json.loads(cross_session_body).get("code") != "csrf_failed"
            or "set-cookie" in cross_session_headers
            or fixture.events != cross_events
            or redis_session(logout_session_key) != logout_record
        ):
            raise RuntimeError("packed BFF accepted cross-session logout CSRF")
        assert_headers(cross_session_headers)

        fixture.revoke_available = True
        revoke_before_concurrency = fixture.revoke_requests
        success_before_concurrency = fixture.revoke_successes
        logout_results = concurrent_logouts(logout_session_id, logout_csrf)
        logout_successes = [result for result in logout_results if result[0] == 303]
        logout_replays = [result for result in logout_results if result[0] == 401]
        if (
            len(logout_successes) != 1
            or len(logout_replays) != 49
            or fixture.revoke_requests != revoke_before_concurrency + 1
            or fixture.revoke_successes != success_before_concurrency + 1
            or run(
                *COMPOSE,
                "exec",
                "-T",
                "redis",
                "redis-cli",
                "EXISTS",
                logout_session_key,
            )
            != "0"
        ):
            summary = Counter(
                (status, json.loads(body).get("code") if body else None)
                for status, _headers, body in logout_results
            )
            raise RuntimeError(f"packed BFF concurrent logout result differs: {summary}")
        success_status, success_headers, success_body = logout_successes[0]
        if success_status != 303 or success_body:
            raise RuntimeError("packed BFF logout success representation differs")
        assert_headers(success_headers, allow_cookie=True)
        assert_logout_redirect(success_headers, fixture_origin)
        assert_bff_clear(success_headers)
        for replay_status, replay_headers, replay_body in logout_replays:
            if (
                replay_status != 401
                or json.loads(replay_body).get("code") != "session_required"
                or "location" in replay_headers
                or logout_csrf.encode() in replay_body
            ):
                raise RuntimeError("packed BFF concurrent logout replay differs")
            assert_headers(replay_headers, allow_cookie=True)
            assert_bff_clear(replay_headers)

        events_before_signed_out = list(fixture.events)
        signed_out_status, signed_out_headers, signed_out_body = request(
            "/auth/signed-out",
            cookie=(f"__Host-oauth={logout_binding}; __Host-session={logout_session_id}"),
        )
        if (
            signed_out_status != 303
            or signed_out_headers.get("location") != "/"
            or signed_out_body
            or fixture.events != events_before_signed_out
        ):
            raise RuntimeError("packed BFF signed-out route crossed an upstream boundary")
        assert_headers(signed_out_headers, allow_cookie=True)
        assert_bff_clear(signed_out_headers)

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
        revoke_before_redis_outage = fixture.revoke_requests
        redis_logout_status, redis_logout_headers, redis_logout_body = request(
            "/auth/logout",
            cookie=f"__Host-session={logout_session_id}",
            method="POST",
            headers={
                "Origin": "http://localhost:8081",
                "X-CSRF-Token": logout_csrf,
                "Sec-Fetch-Site": "same-origin",
            },
        )
        if (
            redis_logout_status != 503
            or json.loads(redis_logout_body).get("code") != "session_unavailable"
            or "location" in redis_logout_headers
            or fixture.revoke_requests != revoke_before_redis_outage
        ):
            raise RuntimeError("packed BFF Redis-outage logout claimed false success")
        assert_headers(redis_logout_headers, allow_cookie=True)
        assert_bff_clear(redis_logout_headers)
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
                "csrf_token",
                "x-csrf-token",
            )
        ) or any(
            value and value in logs
            for value in (
                *fixture.issued_values,
                session_id,
                final_session_id,
                logout_session_id,
                csrf_token,
                race_csrf,
                logout_csrf,
                copied_binding,
                binding,
                denied_binding,
                outage_binding,
                recovery_binding,
                final_binding,
                logout_binding,
                copied_query["state"][0],
                copied_query["nonce"][0],
                query["state"][0],
                query["nonce"][0],
                denied_query["state"][0],
                outage_query["state"][0],
                recovery_query["state"][0],
                final_query["state"][0],
                logout_query["state"][0],
                logout_query["nonce"][0],
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
            "csrf_session_binding=true csrf_header_only=true csrf_no_mutation=true "
            "profile_patch_concurrency_20=true profile_patch_one_success=true "
            "profile_patch_fixed_conflicts=true profile_patch_normalize_clear=true "
            "profile_patch_outage_recovery=true "
            "refresh_single_flight_50=true refresh_version_once=true rotated_refresh=true "
            "stale_cas_rejected=true no_resurrection=true no_lock_residue=true "
            "logout_csrf=true logout_cross_session=true logout_concurrency_50=true "
            "logout_one_delete_revoke=true logout_refresh_race=true "
            "revocation_outage_recovery=true deterministic_logout_redirect=true "
            "signed_out_isolated=true logout_redis_outage=true "
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
