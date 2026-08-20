"""Generate or compare the deterministic operational OpenAPI artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import SecretStr

from identity_service.app import create_app
from identity_service.config import AppEnvironment, Settings

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "openapi" / "openapi.json"


def rendered_openapi() -> str:
    settings = Settings(
        app_env=AppEnvironment.TEST,
        service_version="0.1.0",
        identity_origin="http://localhost:8080",
        allowed_hosts=["localhost", "127.0.0.1", "testserver"],
        trusted_proxy_cidrs=[],
        database_url=SecretStr(
            "postgresql+psycopg://identity_service_app:localapp@localhost:55432/identity_service"  # pragma: allowlist secret (fixed OpenAPI-generation fixture)  # noqa: E501
        ),
        enable_interactive_docs=False,
        metrics_enabled=True,
    )
    document = create_app(settings).openapi()
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = rendered_openapi()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            print("openapi/openapi.json is not deterministic or is out of date")
            return 1
        print("OpenAPI artifact matches generated output")
        return 0
    OUTPUT.write_text(generated)
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
