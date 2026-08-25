"""Exercise the packed reference BFF with disposable Redis and hardened runtime controls."""

from __future__ import annotations

import http.client
import json
import re
import shutil

# Every subprocess invocation is restricted to a resolved Docker executable and fixed arguments.
import subprocess  # nosec B404
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ("compose",)
SECURITY_HEADERS = {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


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


def request(path: str) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", 8081, timeout=3)
    try:
        connection.request("GET", path, headers={"Host": "localhost", "Connection": "close"})
        response = connection.getresponse()
        body = response.read(16_385)
        headers = {name.casefold(): value for name, value in response.getheaders()}
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


def assert_headers(headers: dict[str, str]) -> None:
    if any(headers.get(name) != value for name, value in SECURITY_HEADERS.items()):
        raise RuntimeError("BFF response security headers differ")
    if any(name.startswith("access-control-") for name in headers):
        raise RuntimeError("BFF unexpectedly emitted CORS headers")
    if "set-cookie" in headers:
        raise RuntimeError("BFF unexpectedly emitted a cookie")


def main() -> int:
    try:
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
                "names=('pip','pip3','gcc','cc','make','git','aws','gcloud','terraform','tofu');"
                "print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),"
                "'pip_module':importlib.util.find_spec('pip') is not None,"
                "'pytest_module':importlib.util.find_spec('pytest') is not None,"
                "'identity_module':importlib.util.find_spec('identity_service') is not None,"
                "'paths':{name:shutil.which(name) for name in names}},sort_keys=True))",
            )
        )
        if tooling["uid"] != 10002 or tooling["gid"] != 10002:
            raise RuntimeError("packed BFF process is not the documented non-root identity")
        if tooling["pip_module"] or tooling["pytest_module"] or tooling["identity_module"]:
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
        assert_headers(login_headers)
        redirect = urlsplit(login_headers.get("location", ""))
        query = parse_qs(redirect.query, strict_parsing=True)
        if set(query) != {
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
        }:
            raise RuntimeError("packed BFF redirect fields differ")
        if query.get("code_challenge_method") != ["S256"]:
            raise RuntimeError("packed BFF did not use PKCE S256")
        if re.search(r"(?i)(secret|verifier|transaction|redis|token)", redirect.query):
            raise RuntimeError("packed BFF redirect contains forbidden material")

        run(*COMPOSE, "stop", "-t", "10", "redis")
        wait_for("/health/live", 200)
        wait_for("/health/ready", 503)
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
            marker in logs.casefold() for marker in ("client_secret", "redis://", "code_verifier")
        ):
            raise RuntimeError("packed BFF logs contain forbidden configuration material")
        print(
            "reference BFF packed image passed: "
            f"image={image['Id']} redis={redis_digests[0]} uid_gid=10002:10002 "
            "read_only=true cap_drop=ALL no_new_privileges=true dependency_isolation=true "
            "redis_outage_live=true readiness_recovered=true no_cookie=true no_cors=true "
            f"shutdown_seconds={shutdown_seconds:.3f}"
        )
        return 0
    finally:
        run(*COMPOSE, "down", "--volumes", "--remove-orphans", check=False)


if __name__ == "__main__":
    raise SystemExit(main())
