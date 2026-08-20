"""Lifecycle-aware synchronous facade over httpx2's ASGI transport."""

from __future__ import annotations

import asyncio
from types import TracebackType
from typing import Any, Self

import httpx2
from fastapi import FastAPI


class ASGIClient:
    def __init__(
        self,
        app: FastAPI,
        *,
        base_url: str = "http://testserver",
        raise_app_exceptions: bool = True,
    ) -> None:
        self.app = app
        self.base_url = base_url
        self.raise_app_exceptions = raise_app_exceptions
        self._runner: asyncio.Runner | None = None
        self._client: httpx2.AsyncClient | None = None
        self._lifespan: Any = None

    async def _start(self) -> None:
        self._lifespan = self.app.router.lifespan_context(self.app)
        await self._lifespan.__aenter__()
        self._client = httpx2.AsyncClient(
            transport=httpx2.ASGITransport(
                app=self.app,
                raise_app_exceptions=self.raise_app_exceptions,
                client=("testclient", 50000),
            ),
            base_url=self.base_url,
        )

    def __enter__(self) -> Self:
        self._runner = asyncio.Runner()
        self._runner.run(self._start())
        return self

    async def _stop(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.aclose()
        if self._lifespan is not None:
            await self._lifespan.__aexit__(exc_type, exc_value, traceback)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._runner is None:
            return
        self._runner.run(self._stop(exc_type, exc_value, traceback))
        self._runner.close()

    def request(self, method: str, url: str, **kwargs: Any) -> httpx2.Response:
        if self._runner is None or self._client is None:
            raise RuntimeError("ASGIClient must be used as a context manager")
        return self._runner.run(self._client.request(method, url, **kwargs))

    def get(self, url: str, **kwargs: Any) -> httpx2.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx2.Response:
        return self.request("POST", url, **kwargs)
