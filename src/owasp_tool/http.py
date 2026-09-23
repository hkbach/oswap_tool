import ssl

import httpx

from owasp_tool.config import ScanConfig


def create_client(config: ScanConfig) -> httpx.Client:
    # create_default_context() loads the OS trust store; TLS verification is always on.
    ssl_context = ssl.create_default_context(cafile=config.ca_bundle)
    return httpx.Client(
        timeout=config.timeout,
        verify=ssl_context,
        headers={"User-Agent": config.user_agent},
        follow_redirects=True,
    )
