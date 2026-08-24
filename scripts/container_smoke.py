"""Exercise the packed image with a non-root, read-only runtime filesystem."""

from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import socket

# The runner below permits only a resolved Docker executable and never invokes a shell.
import subprocess  # nosec B404
import time
import uuid
from collections.abc import Mapping
from pathlib import Path

from tests.fixtures.fake_cognito import FakeCognito
from tests.fixtures.fake_cognito_server import FakeCognitoServer

ROOT = Path(__file__).resolve().parents[1]
SMOKE_JSON_PATHS = {
    "/health/live",
    "/health/ready",
    "/openapi.json",
    "/v1/me",
    "/v1/login",
    "/v1/callback",
    "/v1/refresh",
    "/v1/session",
    "/v1/logout",
}
# This exact in-container tmpfs mount target is inspected, not used for host temporary files.
CONTAINER_TMPFS = "/tmp"  # nosec B108
CANONICAL_HOST = "identity.test:8080"
DEPLOYED_CANONICAL_HOST = "identity.test"
COMMON_JSON_LOG_FIELDS = {
    "timestamp",
    "level",
    "logger",
    "message",
    "service",
    "service_version",
    "environment",
}
MAX_RAW_RESPONSE_BYTES = 16 * 1024
RAW_STATUS = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2}) ")
RAW_HTTP_CASES = (
    (
        "conflicting_content_length",
        b"POST /health/live HTTP/1.1\r\nHost: identity.test:8080\r\n"
        b"Content-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde",
    ),
    (
        "content_length_and_chunked",
        b"POST /health/live HTTP/1.1\r\nHost: identity.test:8080\r\n"
        b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        b"0\r\n\r\n",
    ),
    (
        "unsupported_transfer_encoding",
        b"POST /health/live HTTP/1.1\r\nHost: identity.test:8080\r\n"
        b"Transfer-Encoding: gzip\r\nConnection: close\r\n\r\n",
    ),
    (
        "invalid_chunk_with_request_like_suffix",
        b"POST /health/live HTTP/1.1\r\nHost: identity.test:8080\r\n"
        b"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        b"Z\r\ninvalid\r\nGET /health/live HTTP/1.1\r\nHost: identity.test:8080\r\n\r\n",
    ),
    (
        "ambiguous_framing_with_appended_get",
        b"POST /health/live HTTP/1.1\r\nHost: identity.test:8080\r\n"
        b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        b"0\r\n\r\nGET /health/live HTTP/1.1\r\nHost: identity.test:8080\r\n"
        b"Connection: close\r\n\r\n",
    ),
)


def run(
    *args: str,
    capture: bool = False,
    check: bool = True,
    include_stderr: bool = False,
    environment: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> str:
    if not args or args[0] != "docker":
        raise ValueError("the container smoke runner permits only Docker commands")
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker is required for the container smoke test")
    command = (docker, *args[1:])
    # The executable is resolved and the argument vector is passed directly with shell=False.
    result = subprocess.run(  # nosec B603
        command,
        cwd=ROOT,
        check=check,
        capture_output=capture,
        env=environment,
        input=input_text,
        shell=False,
        text=True,
    )
    if not capture:
        return ""
    output = result.stdout
    if include_stderr:
        output += result.stderr or ""
    return output.strip()


def request_json(
    path: str, *, headers: dict[str, str] | None = None
) -> tuple[int, dict[str, object], dict[str, str]]:
    if path not in SMOKE_JSON_PATHS:
        raise ValueError("unsupported smoke-test endpoint")
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=2)
    try:
        request_headers = {"Host": CANONICAL_HOST}
        request_headers.update(headers or {})
        connection.request("GET", path, headers=request_headers)
        response = connection.getresponse()
        payload = json.load(response)
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, payload, response_headers
    finally:
        connection.close()


def request_json_at(
    port: int, path: str, *, host: str
) -> tuple[int, dict[str, object], dict[str, str]]:
    if path not in SMOKE_JSON_PATHS:
        raise ValueError("unsupported smoke-test endpoint")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", path, headers={"Host": host})
        response = connection.getresponse()
        payload = json.load(response)
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, payload, response_headers
    finally:
        connection.close()


def wait_for_json(
    path: str,
    expected_status: str | int,
    *,
    expected_http_status: int = 200,
) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            status, payload, _ = request_json(path)
            if status == expected_http_status and payload.get("status") == expected_status:
                return
        except OSError, json.JSONDecodeError:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"container endpoint did not become healthy: {path}")


def classify_raw_response(response: bytes, *, connection_terminated: bool) -> str:
    statuses = [int(value) for value in RAW_STATUS.findall(response)]
    if len(statuses) > 1:
        raise RuntimeError("ambiguous framing produced more than one HTTP response")
    if any(200 <= status < 300 for status in statuses):
        raise RuntimeError("ambiguous framing produced a successful HTTP response")
    if statuses:
        if not 400 <= statuses[0] < 500:
            raise RuntimeError("ambiguous framing did not produce a safe client error")
        return "client_error"
    if response or not connection_terminated:
        raise RuntimeError("ambiguous framing was neither rejected nor terminated")
    return "connection_terminated"


def send_raw_http(payload: bytes) -> tuple[bytes, bool]:
    response = bytearray()
    connection_terminated = False
    deadline = time.monotonic() + 3
    with socket.create_connection(("127.0.0.1", 8080), timeout=2) as connection:
        connection.settimeout(0.5)
        try:
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
        except BrokenPipeError, ConnectionResetError:
            return b"", True

        while len(response) < MAX_RAW_RESPONSE_BYTES and time.monotonic() < deadline:
            try:
                chunk = connection.recv(min(4096, MAX_RAW_RESPONSE_BYTES - len(response)))
            except TimeoutError:
                continue
            except ConnectionResetError:
                connection_terminated = True
                break
            if not chunk:
                connection_terminated = True
                break
            response.extend(chunk)
    if len(response) >= MAX_RAW_RESPONSE_BYTES:
        raise RuntimeError("ambiguous framing response exceeded the byte bound")
    return bytes(response), connection_terminated


def verify_raw_http_framing() -> list[tuple[str, str, int]]:
    outcomes: list[tuple[str, str, int]] = []
    for case_name, payload in RAW_HTTP_CASES:
        response, terminated = send_raw_http(payload)
        outcome = classify_raw_response(response, connection_terminated=terminated)
        status_lines = len(RAW_STATUS.findall(response))
        live_status, live_payload, _ = request_json("/health/live")
        if live_status != 200 or live_payload != {"status": "alive"}:
            raise RuntimeError("clean liveness failed after an ambiguous framing rejection")
        outcomes.append((case_name, outcome, status_lines))
        print(
            "raw framing passed: "
            f"case={case_name} outcome={outcome} status_lines={status_lines} "
            "appended_request_executed=false clean_liveness=true"
        )
    return outcomes


def _deployed_environment() -> dict[str, str]:
    issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool"
    return {
        "APP_ENV": "development",
        "IDENTITY_ORIGIN": "https://identity.test",
        "ALLOWED_HOSTS": '["identity.test"]',
        "ENABLE_INTERACTIVE_DOCS": "false",
        "LOG_FORMAT": "json",
        "LOG_LEVEL": "INFO",
        "DATABASE_URL": (
            "postgresql+psycopg://database.invalid/identity_service?sslmode=verify-full"
        ),
        "COGNITO_ISSUER": issuer,
        "COGNITO_JWKS_URL": issuer + "/.well-known/jwks.json",
        "COGNITO_USERINFO_URL": ("https://cognito-idp.us-east-1.amazonaws.com/oauth2/userInfo"),
        "COGNITO_ALLOWED_CLIENT_IDS": '["packed-smoke-client"]',
    }


def _verify_rejected_configuration(
    image_id: str,
    *,
    category: str,
    overrides: Mapping[str, str],
    expected_field: str,
    prohibited_output: tuple[str, ...],
) -> None:
    container_name = f"identity-service-invalid-config-{uuid.uuid4().hex}"
    environment = os.environ.copy()
    configuration = _deployed_environment()
    configuration.update(overrides)
    environment.update(configuration)
    try:
        arguments = [
            "docker",
            "create",
            "--name",
            container_name,
        ]
        for key in configuration:
            arguments.extend(("--env", key))
        arguments.append(image_id)
        run(*arguments, capture=True, environment=environment)
        output = run(
            "docker",
            "start",
            "--attach",
            container_name,
            capture=True,
            check=False,
            include_stderr=True,
        )
        exit_code = run(
            "docker",
            "inspect",
            "--format={{.State.ExitCode}}",
            container_name,
            capture=True,
        )
        if exit_code == "0":
            raise RuntimeError(f"rejected configuration started successfully: {category}")
        if any(value and value in output for value in prohibited_output):
            raise RuntimeError(f"rejected configuration leaked an input value: {category}")
        if expected_field not in output:
            raise RuntimeError(f"rejected configuration did not identify its field: {category}")
    finally:
        run("docker", "rm", "--force", container_name, capture=True, check=False)


def verify_invalid_configuration_redaction(image_id: str) -> None:
    origin_sentinel = f"startup-output-redaction-{uuid.uuid4().hex}"
    _verify_rejected_configuration(
        image_id,
        category="identity_origin",
        overrides={
            "IDENTITY_ORIGIN": f"https://user:{origin_sentinel}@identity.invalid",
            "ALLOWED_HOSTS": '["identity.invalid"]',
        },
        expected_field="IDENTITY_ORIGIN",
        prohibited_output=(origin_sentinel,),
    )

    hostless_url = "postgresql+psycopg:///identity_service?sslmode=verify-full"
    _verify_rejected_configuration(
        image_id,
        category="hostless_database_url",
        overrides={"DATABASE_URL": hostless_url},
        expected_field="DATABASE_URL",
        prohibited_output=(hostless_url,),
    )

    sentinel = f"database-output-redaction-{uuid.uuid4().hex}"
    username = f"database-user-{uuid.uuid4().hex}"
    socket_path = f"{CONTAINER_TMPFS}/database-socket-{uuid.uuid4().hex}"
    socket_url = (
        f"postgresql+psycopg://{username}:{sentinel}@/identity_service"
        f"?host={socket_path}&sslmode=verify-full"
    )
    _verify_rejected_configuration(
        image_id,
        category="unix_socket_database_url",
        overrides={"DATABASE_URL": socket_url},
        expected_field="DATABASE_URL",
        prohibited_output=(socket_url, sentinel, username, socket_path),
    )
    print("packed startup redaction passed: categories=3 database_destination_rejections=2")


def _parse_container_json_logs(container_name: str) -> list[dict[str, object]]:
    output = run("docker", "logs", container_name, capture=True, check=False, include_stderr=True)
    records: list[dict[str, object]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        if "\x1b" in line:
            raise RuntimeError("deployed container emitted an ANSI-prefixed log line")
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            raise RuntimeError("deployed container emitted a non-JSON log line") from None
        if not isinstance(record, dict):
            raise RuntimeError("deployed container emitted a non-object JSON log record")
        records.append(record)
    return records


def _wait_for_container_log_event(container_name: str, expected_event: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        records = _parse_container_json_logs(container_name)
        if any(record.get("event") == expected_event for record in records):
            return
        state = run(
            "docker",
            "inspect",
            "--format={{.State.Status}}",
            container_name,
            capture=True,
        )
        if state == "exited":
            raise RuntimeError("deployed JSON-log container exited before startup completed")
        time.sleep(0.2)
    raise RuntimeError("deployed JSON-log container did not report startup completion")


def verify_deployed_json_logging(image_id: str) -> tuple[int, float]:
    container_name = f"identity-service-json-logging-{uuid.uuid4().hex}"
    environment = os.environ.copy()
    configuration = _deployed_environment()
    environment.update(configuration)
    created = False
    try:
        arguments = [
            "docker",
            "create",
            "--name",
            container_name,
            "--init",
            "--read-only",
            "--tmpfs",
            f"{CONTAINER_TMPFS}:rw,noexec,nosuid,nodev,size=16m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--no-healthcheck",
            "--publish",
            "127.0.0.1::8080",
        ]
        for key in configuration:
            arguments.extend(("--env", key))
        arguments.append(image_id)
        run(*arguments, capture=True, environment=environment)
        created = True
        run("docker", "start", container_name, capture=True)
        _wait_for_container_log_event(container_name, "server_listening")

        published = run("docker", "port", container_name, "8080/tcp", capture=True)
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", published)
        if match is None:
            raise RuntimeError("deployed JSON-log container did not expose one loopback port")
        published_port = int(match.group(1))
        status, payload, _ = request_json_at(
            published_port, "/health/live", host=DEPLOYED_CANONICAL_HOST
        )
        if status != 200 or payload != {"status": "alive"}:
            raise RuntimeError("deployed JSON-log liveness request failed")

        shutdown_started = time.monotonic()
        run("docker", "stop", "--timeout", "20", container_name, capture=True)
        shutdown_seconds = time.monotonic() - shutdown_started
        state = json.loads(
            run(
                "docker",
                "inspect",
                "--format={{json .State}}",
                container_name,
                capture=True,
            )
        )
        records = _parse_container_json_logs(container_name)
        if not records:
            raise RuntimeError("deployed JSON-log container produced no records")
        for record in records:
            if not set(record) >= COMMON_JSON_LOG_FIELDS:
                raise RuntimeError("deployed JSON record omitted required common fields")
            if (
                record["service"] != "identity-service"
                or record["service_version"] != "0.1.0"
                or record["environment"] != "development"
            ):
                raise RuntimeError("deployed JSON record contained incorrect common fields")

        lifecycle_events = (
            "server_started",
            "application_startup_complete",
            "server_listening",
            "server_shutdown_started",
            "application_shutdown_complete",
            "server_stopped",
        )
        for event in lifecycle_events:
            if sum(record.get("event") == event for record in records) != 1:
                raise RuntimeError("deployed lifecycle event was missing or duplicated")
        request_records = [
            record
            for record in records
            if record.get("logger") == "identity_service.http"
            and record.get("event") == "request_complete"
        ]
        if len(request_records) != 1:
            raise RuntimeError("deployed request completion record was missing or duplicated")
        if any(record.get("logger") == "uvicorn.access" for record in records):
            raise RuntimeError("deployed container emitted a Uvicorn access-log record")
        if not any(record.get("logger") == "uvicorn.error" for record in records):
            raise RuntimeError("deployed container omitted Uvicorn lifecycle logging")
        if (
            state["Running"]
            or state["ExitCode"] not in {0, 143}
            or state["OOMKilled"]
            or shutdown_seconds >= 20
        ):
            raise RuntimeError("deployed JSON-log container did not shut down cleanly")

        print(
            "packed JSON logging passed: "
            f"records={len(records)} common_fields=true lifecycle_events=6 "
            "request_completion_records=1 access_records=0 duplicates=0 plain_text=0 "
            f"shutdown_exit={state['ExitCode']} shutdown_seconds={shutdown_seconds:.3f}"
        )
        return int(state["ExitCode"]), shutdown_seconds
    finally:
        if created:
            run("docker", "rm", "--force", container_name, capture=True, check=False)


def fixture_environment(port: int) -> dict[str, str]:
    issuer = f"http://host.docker.internal:{port}/test-pool"
    return {
        "COGNITO_ISSUER": issuer,
        "COGNITO_JWKS_URL": issuer + "/.well-known/jwks.json",
        "COGNITO_USERINFO_URL": f"http://host.docker.internal:{port}/oauth2/userInfo",
        "COGNITO_ALLOWED_CLIENT_IDS": '["fixture-client"]',
        "JWKS_CACHE_MAX_AGE_SECONDS": "1",
        "JWKS_STALE_IF_ERROR_SECONDS": "3",
        "JWKS_REFRESH_MIN_INTERVAL_SECONDS": "1",
    }


def request_metrics() -> tuple[int, str]:
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=2)
    try:
        connection.request("GET", "/metrics", headers={"Host": CANONICAL_HOST})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


def wait_for_jwks_cache_state(
    fake_cognito: FakeCognito,
    expected_state: str,
    *,
    expected_ready: bool,
    minimum_fetches: int = 0,
) -> None:
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            ready_status, _, _ = request_json("/health/ready")
            metrics_status, metrics_text = request_metrics()
            state_line = f'identity_service_jwks_cache_state{{state="{expected_state}"}} 1.0'
            if (
                metrics_status == 200
                and state_line in metrics_text
                and (ready_status == 200) is expected_ready
                and fake_cognito.jwks_fetches >= minimum_fetches
            ):
                return
        except OSError, json.JSONDecodeError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"JWKS cache did not reach the expected {expected_state} state")


def verify_packed_access_token(raw_token: str, expected_outcome: str) -> None:
    probe = (
        "import sys\n"
        "from identity_service.config import Settings\n"
        "from identity_service.observability import Metrics\n"
        "from identity_service.security import AccessTokenVerifier,JwksCache,UpstreamHttpClient\n"
        "from identity_service.security.errors import SecurityCoreError,"
        "TokenVerificationUnavailableError\n"
        "settings=Settings()\n"
        "client=UpstreamHttpClient(settings)\n"
        "cache=JwksCache(settings,client,metrics=Metrics())\n"
        "try:\n"
        "    try:\n"
        "        AccessTokenVerifier(settings,cache).verify_access_token(sys.stdin.read())\n"
        "    except TokenVerificationUnavailableError:\n"
        "        outcome='dependency_unavailable'\n"
        "    except SecurityCoreError:\n"
        "        outcome='rejected'\n"
        "    else:\n"
        "        outcome='verified'\n"
        "finally:\n"
        "    cache.close()\n"
        "    client.close()\n"
        "print(outcome)"
    )
    outcome = run(
        "docker",
        "compose",
        "exec",
        "-T",
        "app",
        "python",
        "-c",
        probe,
        capture=True,
        input_text=raw_token,
    )
    if outcome != expected_outcome:
        raise RuntimeError("packed access-token verification returned an unsafe outcome")


def verify_packed_jwks_outage_and_recovery(fake_cognito: FakeCognito) -> None:
    initial_failure_fetches = fake_cognito.jwks_fetches
    wait_for_jwks_cache_state(
        fake_cognito,
        "unavailable",
        expected_ready=False,
        minimum_fetches=initial_failure_fetches + 1,
    )
    verify_packed_access_token(fake_cognito.token(), "dependency_unavailable")

    fake_cognito.jwks_status = 200
    recovery_fetches = fake_cognito.jwks_fetches
    wait_for_jwks_cache_state(
        fake_cognito,
        "fresh",
        expected_ready=True,
        minimum_fetches=recovery_fetches + 1,
    )
    verify_packed_access_token(fake_cognito.token(), "verified")

    fake_cognito.rotate("packed-rotated-key", retain_old=False)
    rotated_token = fake_cognito.token()
    fake_cognito.jwks_status = 500
    verify_packed_access_token(rotated_token, "dependency_unavailable")
    fake_cognito.jwks_status = 200
    verify_packed_access_token(rotated_token, "verified")
    rotation_fetches = fake_cognito.jwks_fetches
    wait_for_jwks_cache_state(
        fake_cognito,
        "fresh",
        expected_ready=True,
        minimum_fetches=rotation_fetches + 1,
    )

    fake_cognito.jwks_mode = "malformed_json"
    malformed_fetches = fake_cognito.jwks_fetches
    wait_for_jwks_cache_state(
        fake_cognito,
        "degraded",
        expected_ready=True,
        minimum_fetches=malformed_fetches + 1,
    )
    fake_cognito.jwks_mode = "valid"
    repaired_fetches = fake_cognito.jwks_fetches
    wait_for_jwks_cache_state(
        fake_cognito,
        "fresh",
        expected_ready=True,
        minimum_fetches=repaired_fetches + 1,
    )

    fake_cognito.jwks_status = 500
    outage_fetches = fake_cognito.jwks_fetches
    wait_for_jwks_cache_state(
        fake_cognito,
        "degraded",
        expected_ready=True,
        minimum_fetches=outage_fetches + 1,
    )
    wait_for_jwks_cache_state(fake_cognito, "unavailable", expected_ready=False)
    fake_cognito.jwks_status = 200
    final_recovery_fetches = fake_cognito.jwks_fetches
    wait_for_jwks_cache_state(
        fake_cognito,
        "fresh",
        expected_ready=True,
        minimum_fetches=final_recovery_fetches + 1,
    )
    if fake_cognito.jwks_fetches < 8:
        raise RuntimeError("packed JWKS outage/recovery did not perform bounded refreshes")
    print(
        "packed JWKS passed: initial_outage=unavailable initial_recovery=fresh "
        "rotated_token_outage=dependency_unavailable rotation_refresh=verified "
        "malformed_refresh=prior_snapshot_preserved outage=degraded "
        f"hard_stale=unavailable final_recovery=fresh fetches={fake_cognito.jwks_fetches}"
    )


def main() -> int:
    fake_cognito = FakeCognito()
    fake_server = FakeCognitoServer(fake_cognito)
    fake_server.start()
    environment_overrides = fixture_environment(fake_server.port)
    fake_cognito.issuer = environment_overrides["COGNITO_ISSUER"]
    fake_cognito.jwks_url = environment_overrides["COGNITO_JWKS_URL"]
    fake_cognito.userinfo_url = environment_overrides["COGNITO_USERINFO_URL"]
    fake_cognito.jwks_status = 500
    previous_environment = {key: os.environ.get(key) for key in environment_overrides}
    os.environ.update(environment_overrides)
    try:
        run("docker", "compose", "up", "-d", "--wait", "db")
        run("docker", "compose", "run", "--rm", "migrate")
        run("docker", "compose", "up", "-d", "--wait", "app")
        wait_for_json("/health/live", "alive")
        verify_packed_jwks_outage_and_recovery(fake_cognito)

        container_id = run("docker", "compose", "ps", "-q", "app", capture=True)
        if not container_id:
            raise RuntimeError("application container ID was not available")
        container = json.loads(run("docker", "inspect", container_id, capture=True))[0]
        host_config = container["HostConfig"]
        if container["State"].get("Health", {}).get("Status") != "healthy":
            raise RuntimeError("packed image did not become Docker-healthy")
        if container["Config"]["User"] != "10001:10001":
            raise RuntimeError("packed image did not retain the documented UID/GID")
        if not host_config["ReadonlyRootfs"]:
            raise RuntimeError("application root filesystem was not mounted read-only")
        if {value.upper() for value in host_config.get("CapDrop") or []} != {"ALL"}:
            raise RuntimeError("application container did not drop every capability")
        if "no-new-privileges:true" not in (host_config.get("SecurityOpt") or []):
            raise RuntimeError("application container did not enable no-new-privileges")
        if set(host_config.get("Tmpfs") or {}) != {CONTAINER_TMPFS}:
            raise RuntimeError("the documented path was not the sole explicitly writable tmpfs")

        identity = run(
            "docker",
            "compose",
            "exec",
            "-T",
            "app",
            "python",
            "-c",
            "import os; print(f'{os.geteuid()}:{os.getegid()}')",
            capture=True,
        )
        if identity != "10001:10001":
            raise RuntimeError("application process is not running as UID/GID 10001")

        filesystem_probe = (
            "import json\n"
            "from pathlib import Path\n"
            "targets={'/tmp/identity-smoke': True, '/identity-smoke': False, "
            "'/app/identity-smoke': False, '/opt/venv/identity-smoke': False}\n"
            "results={}\n"
            "for raw, expected in targets.items():\n"
            "    path=Path(raw)\n"
            "    try:\n"
            "        path.write_text('probe')\n"
            "    except OSError:\n"
            "        results[raw]=False\n"
            "    else:\n"
            "        results[raw]=True\n"
            "        path.unlink()\n"
            "print(json.dumps(results, sort_keys=True))"
        )
        filesystem = json.loads(
            run(
                "docker",
                "compose",
                "exec",
                "-T",
                "app",
                "python",
                "-c",
                filesystem_probe,
                capture=True,
            )
        )
        expected_filesystem = {
            f"{CONTAINER_TMPFS}/identity-smoke": True,
            "/identity-smoke": False,
            "/app/identity-smoke": False,
            "/opt/venv/identity-smoke": False,
        }
        if filesystem != expected_filesystem:
            raise RuntimeError("runtime filesystem write boundary was not enforced")

        tooling_probe = (
            "import importlib.metadata,importlib.util,json,shutil; "
            "names=('pip','pip3','gcc','cc','make','git','aws','gcloud','terraform'); "
            "print(json.dumps({'paths':{name:shutil.which(name) for name in names},"
            "'pip_module':importlib.util.find_spec('pip') is not None,"
            "'security_dependencies':{name:importlib.metadata.version(name) for name in "
            "('PyJWT','cryptography','httpx2')}},sort_keys=True))"
        )
        tooling = json.loads(
            run(
                "docker",
                "compose",
                "exec",
                "-T",
                "app",
                "python",
                "-c",
                tooling_probe,
                capture=True,
            )
        )
        if tooling["pip_module"] or any(tooling["paths"].values()):
            raise RuntimeError(
                "build, package, VCS, cloud, or deployment tooling remains in runtime"
            )
        if tooling["security_dependencies"] != {
            "PyJWT": "2.13.0",
            "cryptography": "50.0.0",
            "httpx2": "2.12.0",
        }:
            raise RuntimeError("packed runtime security dependencies do not match the lock")

        artifact_probe = (
            "import json\n"
            "from pathlib import Path\n"
            "blocked={'.git','.env','.pytest_cache','.mypy_cache','.ruff_cache','.coverage',"
            "'coverage.xml','tests'}\n"
            "found=[]\n"
            "for path in Path('/app').rglob('*'):\n"
            "    if path.name in blocked or 'fake_cognito' in path.name or path.suffix == '.key':\n"
            "        found.append(str(path))\n"
            "    elif path.is_file() and path.stat().st_size <= 1048576:\n"
            "        if b'PRIVATE KEY' in path.read_bytes():\n"
            "            found.append(str(path))\n"
            "print(json.dumps(found))"
        )
        artifacts = json.loads(
            run(
                "docker",
                "compose",
                "exec",
                "-T",
                "app",
                "python",
                "-c",
                artifact_probe,
                capture=True,
            )
        )
        if artifacts:
            raise RuntimeError("VCS, environment, test, or coverage artifacts exist in runtime")

        image = json.loads(
            run("docker", "image", "inspect", "identity-service:local", capture=True)
        )[0]
        forbidden_env_keys = ("PASSWORD", "SECRET", "TOKEN", "DATABASE_URL", "AWS_", "GOOGLE_")
        image_environment = image["Config"].get("Env") or []
        if any(
            item.partition("=")[0].upper().startswith(forbidden_env_keys)
            for item in image_environment
        ):
            raise RuntimeError("credential-bearing environment metadata was baked into the image")
        verify_invalid_configuration_redaction(image["Id"])
        json_shutdown_exit, json_shutdown_seconds = verify_deployed_json_logging(image["Id"])

        process_probe = (
            "from pathlib import Path; "
            "commands=[p.read_bytes().split(b'\\0') "
            "for p in Path('/proc').glob('[0-9]*/cmdline')]; "
            "matches=[parts for parts in commands if len(parts) >= 3 and "
            "parts[0].endswith(b'python') and "
            "parts[1:3] == [b'-m', b'identity_service.server']]; print(len(matches))"
        )
        process_count = run(
            "docker",
            "compose",
            "exec",
            "-T",
            "app",
            "python",
            "-c",
            process_probe,
            capture=True,
        )
        if process_count != "1":
            raise RuntimeError("packed container does not have exactly one application process")

        request_id = str(uuid.uuid4())
        live_status, _, live_headers = request_json(
            "/health/live",
            headers={"Origin": "https://browser.invalid", "X-Request-ID": request_id},
        )
        if live_status != 200 or live_headers.get("x-request-id") != request_id:
            raise RuntimeError("packed liveness/request-ID contract failed")
        if "access-control-allow-origin" in live_headers:
            raise RuntimeError("packed application unexpectedly emitted a CORS allow header")
        openapi_status, openapi, _ = request_json("/openapi.json")
        if openapi_status != 200 or set(openapi.get("paths", {})) != {
            "/health/live",
            "/health/ready",
            "/metrics",
        }:
            raise RuntimeError("packed OpenAPI contains an unexpected route surface")
        for absent_path in (
            "/v1/me",
            "/v1/login",
            "/v1/callback",
            "/v1/refresh",
            "/v1/session",
            "/v1/logout",
        ):
            absent_status, absent_payload, absent_headers = request_json(absent_path)
            if (
                absent_status != 404
                or absent_payload.get("code") != "not_found"
                or not absent_headers.get("content-type", "").startswith("application/problem+json")
            ):
                raise RuntimeError(f"packed image unexpectedly exposes {absent_path}")
        invalid_host_status, _, invalid_host_headers = request_json(
            "/health/live", headers={"Host": "attacker.invalid"}
        )
        if invalid_host_status != 400 or not invalid_host_headers.get(
            "content-type", ""
        ).startswith("application/problem+json"):
            raise RuntimeError("packed invalid-host rejection contract failed")
        loopback_status, _, _ = request_json("/health/live", headers={"Host": "127.0.0.1"})
        if loopback_status != 400:
            raise RuntimeError("packed application unexpectedly allowlisted loopback Host")
        local_status, local_payload, _ = request_json(
            "/health/live", headers={"Host": "localhost:8080"}
        )
        if local_status != 200 or local_payload != {"status": "alive"}:
            raise RuntimeError("documented localhost Host did not retain local access")

        raw_outcomes = verify_raw_http_framing()
        if len(raw_outcomes) != len(RAW_HTTP_CASES):
            raise RuntimeError("not every raw HTTP framing case completed")

        run("docker", "compose", "stop", "-t", "10", "db")
        wait_for_json("/health/live", "alive")
        run("docker", "compose", "exec", "-T", "app", "python", "scripts/healthcheck.py")
        wait_for_json("/health/ready", 503, expected_http_status=503)
        run("docker", "compose", "up", "-d", "--wait", "db")
        wait_for_json("/health/ready", "ready")

        shutdown_started = time.monotonic()
        run("docker", "stop", "--timeout", "20", container_id, capture=True)
        shutdown_seconds = time.monotonic() - shutdown_started
        state = json.loads(run("docker", "inspect", container_id, capture=True))[0]["State"]
        shutdown_logs = run("docker", "logs", container_id, capture=True, include_stderr=True)
        if (
            re.search(
                r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
                shutdown_logs,
            )
            or re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", shutdown_logs)
            or any(
                value in shutdown_logs
                for value in (
                    fake_cognito.active_kid,
                    "fixture-key-1",
                    "opaque-Subject_1",
                )
            )
        ):
            raise RuntimeError("packed container logs exposed identity or key material")
        graceful_markers = (
            "Shutting down",
            "Waiting for application shutdown",
            "Application shutdown complete",
            "Finished server process",
        )
        if (
            state["Running"]
            or state["ExitCode"] not in {0, 143}
            or state["OOMKilled"]
            or not all(marker in shutdown_logs for marker in graceful_markers)
        ):
            raise RuntimeError("SIGTERM did not produce a clean bounded application shutdown")
        if shutdown_seconds >= 20:
            raise RuntimeError("SIGTERM shutdown exceeded the configured Docker bound")

        print(
            "packed image passed: "
            f"image={image['Id']} uid_gid={identity} read_only=true tmpfs=/tmp "
            "cap_drop=ALL no_new_privileges=true app_processes=1 "
            "runtime_security_dependencies=true fixture_excluded=true private_keys_absent=true "
            f"canonical_health_host=true loopback_host_rejected=true outage_recovery=true "
            f"startup_redaction=true raw_http_cases={len(raw_outcomes)} "
            f"deployed_json_logging=true json_shutdown_exit={json_shutdown_exit} "
            f"json_shutdown_seconds={json_shutdown_seconds:.3f} "
            f"shutdown_exit={state['ExitCode']} "
            f"shutdown_seconds={shutdown_seconds:.3f}"
        )
        return 0
    finally:
        run("docker", "compose", "down", "--volumes", "--remove-orphans", check=False)
        for key, previous_value in previous_environment.items():
            if previous_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous_value
        fake_server.close()


if __name__ == "__main__":
    raise SystemExit(main())
