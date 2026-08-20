"""One-process Uvicorn entry point with explicit proxy and shutdown behavior."""

import ipaddress

import uvicorn

from identity_service.config import Settings
from identity_service.observability import configure_logging


def main() -> None:
    settings = Settings()
    configure_logging(settings)
    uvicorn.run(
        "identity_service.main:app",
        host=str(ipaddress.IPv4Address(0)),
        port=settings.port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        log_config=None,
        log_level=None,
        timeout_graceful_shutdown=settings.graceful_shutdown_seconds,
    )


if __name__ == "__main__":
    main()
