"""What the scanner takes from an API spec: servers, endpoints, parameters, security schemes (FR-API-01d, D9).

The inventory is built from the spec alone. Nothing is requested from any server or endpoint it
names, and only names and structure are taken: never an example, a default, a description or a
schema, which is where a spec keeps sample secrets (and where a ``$ref`` is most likely to point
somewhere it should not, so schemas are not resolved at all).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .spec_loader import Spec, SpecError, load_spec

MAX_ENDPOINTS = 2_000
MAX_PARAMETERS = 100  # on one operation, path-level and operation-level together

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_PARAMETER_LOCATIONS = ("query", "header", "path", "cookie", "formData", "body")
_VARIABLE = re.compile(r"\{([^{}]+)\}")


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str  # the "in" of the spec
    required: bool


@dataclass(frozen=True)
class Endpoint:
    method: str  # upper case
    path: str
    operation_id: str | None
    parameters: tuple[Parameter, ...]
    security: tuple[str, ...]  # names of the schemes that apply, after the global default
    deprecated: bool


@dataclass(frozen=True)
class SecurityScheme:
    name: str
    type: str
    detail: str


@dataclass(frozen=True)
class ApiInventory:
    source: str  # the file name only, never a local path
    kind: str  # "openapi" or "swagger"
    version: str
    title: str
    servers: tuple[str, ...]
    security_schemes: tuple[SecurityScheme, ...]
    endpoints: tuple[Endpoint, ...]

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    def to_dict(self, redact: Callable[[str], str] | None = None) -> dict:
        """The ``api`` object of the JSON report. ``redact`` is applied to every text taken from the spec."""

        def text(value: str) -> str:
            return redact(value) if redact else value

        return {
            "source": text(self.source),
            "format": self.kind,
            "version": self.version,
            "title": text(self.title),
            "servers": [text(server) for server in self.servers],
            "security_schemes": [
                {"name": text(s.name), "type": text(s.type), "detail": text(s.detail)} for s in self.security_schemes
            ],
            "endpoint_count": self.endpoint_count,
            "endpoints": [
                {
                    "method": e.method,
                    "path": text(e.path),
                    "operation_id": None if e.operation_id is None else text(e.operation_id),
                    "parameters": [
                        {"name": text(p.name), "in": p.location, "required": p.required} for p in e.parameters
                    ],
                    "security": [text(name) for name in e.security],
                    "deprecated": e.deprecated,
                }
                for e in self.endpoints
            ],
        }


def _mapping(value: Any, where: str) -> dict:
    if not isinstance(value, dict):
        raise SpecError(f"{where} must be an object")
    return value


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


# --- servers --------------------------------------------------------------------------------------------------------


def _fill_variables(url: str, variables: Any) -> str:
    variables = variables if isinstance(variables, dict) else {}

    def replace(match: re.Match) -> str:
        spec = variables.get(match.group(1))
        default = spec.get("default") if isinstance(spec, dict) else None
        return (
            str(default) if isinstance(default, (str, int, float)) and not isinstance(default, bool) else match.group(0)
        )

    return _VARIABLE.sub(replace, url)


def _servers(spec: Spec) -> tuple[str, ...]:
    document = spec.document
    if spec.kind == "swagger":
        base = _text(document.get("basePath"))
        host = _text(document.get("host"))
        if not host:
            return (base or "/",)
        schemes = document.get("schemes")
        schemes = [s for s in schemes if isinstance(s, str)] if isinstance(schemes, list) else []
        return tuple(f"{scheme}://{host}{base}" for scheme in (schemes or ["https"]))
    raw = document.get("servers")
    if raw is None:
        return ("/",)
    if not isinstance(raw, list):
        raise SpecError("'servers' must be a list")
    servers = []
    for entry in raw:
        server, _ = spec.follow(entry, spec.path)
        server = _mapping(server, "a server in 'servers'")
        url = server.get("url")
        if not isinstance(url, str):
            raise SpecError("a server in 'servers' has no 'url'")
        servers.append(_fill_variables(url, server.get("variables")))
    return tuple(servers) or ("/",)


# --- security -------------------------------------------------------------------------------------------------------


def _scheme_detail(kind: str, scheme: dict) -> str:
    if kind == "apiKey":
        return " ".join(part for part in (_text(scheme.get("in")), _text(scheme.get("name"))) if part)
    if kind == "http":
        return _text(scheme.get("scheme")).lower()
    if kind == "oauth2":
        flows = scheme.get("flows")
        if isinstance(flows, dict):  # OpenAPI 3: authorizationCode, clientCredentials, ...
            return ", ".join(sorted(str(name) for name in flows))
        return _text(scheme.get("flow"))  # Swagger 2: implicit, password, application, accessCode
    return ""


def _security_schemes(spec: Spec) -> tuple[SecurityScheme, ...]:
    document = spec.document
    if spec.kind == "swagger":
        raw, label = document.get("securityDefinitions"), "'securityDefinitions'"
    else:
        components = document.get("components")
        if components is None:
            return ()
        raw, label = _mapping(components, "'components'").get("securitySchemes"), "'securitySchemes'"
    if raw is None:
        return ()
    schemes = []
    for name, entry in _mapping(raw, label).items():
        scheme, _ = spec.follow(entry, spec.path)
        scheme = _mapping(scheme, f"security scheme {name!r}")
        kind = _text(scheme.get("type"))
        schemes.append(SecurityScheme(name, kind, _scheme_detail(kind, scheme)))
    return tuple(sorted(schemes, key=lambda s: s.name))


def _security_names(raw: Any, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise SpecError(f"{where} must be a list")
    names: set[str] = set()
    for requirement in raw:
        names.update(_mapping(requirement, f"an entry of {where}"))
    return tuple(sorted(names))


# --- parameters -----------------------------------------------------------------------------------------------------


def _parameters(spec: Spec, raw: Any, base: Path, where: str) -> dict[tuple[str, str], Parameter]:
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise SpecError(f"'parameters' of {where} must be a list")
    found: dict[tuple[str, str], Parameter] = {}
    for entry in raw:
        item, _ = spec.follow(entry, base)
        item = _mapping(item, f"a parameter of {where}")
        name, location = item.get("name"), item.get("in")
        if not isinstance(name, str) or not name:
            raise SpecError(f"a parameter of {where} has no 'name'")
        if not isinstance(location, str):
            raise SpecError(f"the parameter {name!r} of {where} has no 'in'")
        if location not in _PARAMETER_LOCATIONS:
            raise SpecError(f"the parameter {name!r} of {where} has an unknown location {location!r}")
        found[(name, location)] = Parameter(name, location, item.get("required") is True)
    return found


# --- endpoints ------------------------------------------------------------------------------------------------------


def _endpoints(spec: Spec, global_security: tuple[str, ...]) -> tuple[Endpoint, ...]:
    raw_paths = spec.document.get("paths")
    if raw_paths is None:
        return ()
    paths = _mapping(raw_paths, "'paths'")
    endpoints: list[Endpoint] = []
    for path in sorted(paths):
        if path.startswith("x-"):
            continue
        item, item_base = spec.follow(paths[path], spec.path)
        item = _mapping(item, f"the path item {path!r}")
        inherited = _parameters(spec, item.get("parameters"), item_base, f"the path {path}")
        for method in sorted(m for m in _HTTP_METHODS if m in item):
            where = f"{method.upper()} {path}"
            operation, operation_base = spec.follow(item[method], item_base)
            operation = _mapping(operation, f"the operation {where}")
            own = _parameters(spec, operation.get("parameters"), operation_base, where)
            merged = {**inherited, **own}
            if len(merged) > MAX_PARAMETERS:
                raise SpecError(f"too many parameters on {where} (limit {MAX_PARAMETERS})")
            security = (
                _security_names(operation["security"], f"'security' of {where}")
                if "security" in operation
                else global_security
            )
            operation_id = operation.get("operationId")
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    operation_id=operation_id if isinstance(operation_id, str) else None,
                    parameters=tuple(sorted(merged.values(), key=lambda p: (p.location, p.name))),
                    security=security,
                    deprecated=operation.get("deprecated") is True,
                )
            )
            if len(endpoints) > MAX_ENDPOINTS:
                raise SpecError(f"too many endpoints (more than {MAX_ENDPOINTS:,}); split the spec or raise the limit")
    return tuple(endpoints)


def build_inventory(path: str | Path) -> ApiInventory:
    """Read a spec file and list what it describes. Raises SpecError for anything wrong with it.

    Every error names the file: the loader's own errors already do, and a problem found while
    listing (a forbidden ``$ref``, a malformed parameter) gets the spec's file name in front.
    """
    spec = load_spec(path)
    try:
        info = spec.document.get("info")
        title = _text(info.get("title")) if isinstance(info, dict) else ""
        global_security = (
            _security_names(spec.document["security"], "'security'") if "security" in spec.document else ()
        )
        return ApiInventory(
            source=spec.path.name,
            kind=spec.kind,
            version=spec.version,
            title=title,
            servers=_servers(spec),
            security_schemes=_security_schemes(spec),
            endpoints=_endpoints(spec, global_security),
        )
    except SpecError as exc:
        raise SpecError(f"{spec.path.name}: {exc}") from None
