from abc import ABC, abstractmethod

import httpx

from owasp_tool.models import Finding


class Check(ABC):
    """Base class for all checks. Subclasses must be registered in checks/__init__.py."""

    id: str
    name: str
    owasp: str
    description: str = ""

    @abstractmethod
    def run(self, client: httpx.Client, target: str) -> list[Finding]:
        """Run the check against target and return any findings."""
