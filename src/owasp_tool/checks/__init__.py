from collections.abc import Iterable

from owasp_tool.checks.base import Check
from owasp_tool.checks.security_headers import SecurityHeadersCheck

ALL_CHECKS: tuple[type[Check], ...] = (SecurityHeadersCheck,)


def get_checks(ids: Iterable[str] | None = None) -> list[Check]:
    """Return check instances, all of them or only the given ids."""
    registry = {cls.id: cls for cls in ALL_CHECKS}
    if ids is None:
        return [cls() for cls in ALL_CHECKS]
    ids = list(ids)
    unknown = [i for i in ids if i not in registry]
    if unknown:
        raise ValueError(f"Unknown check id(s): {', '.join(unknown)}")
    return [registry[i]() for i in ids]
