from collections.abc import Callable

import httpx
import pytest


@pytest.fixture
def mock_client() -> Callable[..., httpx.Client]:
    """Build an httpx.Client that returns a canned response without network access."""

    def factory(status_code: int = 200, headers: dict[str, str] | None = None) -> httpx.Client:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, headers=headers or {})

        return httpx.Client(transport=httpx.MockTransport(handler))

    return factory
