from dataclasses import dataclass

from owasp_tool import __version__


@dataclass(frozen=True)
class ScanConfig:
    timeout: float = 10.0
    user_agent: str = f"owasp-tool/{__version__}"
    # Custom CA bundle (e.g. corporate proxy CA). None uses the OS trust store.
    ca_bundle: str | None = None
