"""The ``--config`` file: every command-line option in one TOML file (FR-CI-06).

Example ``scanner.toml``::

    targets = ["https://staging.example.com/"]
    checks = ["headers", "tls", "cookies"]
    fail_on = "medium"
    rate_limit = 5
    output_dir = "reports"           # relative to this file, not to the working directory
    formats = ["json", "sarif"]

    [headers]
    Authorization = "Bearer ${SCANNER_TOKEN}"   # from the environment, never written here

Rules, all enforced here so a mistake fails before any request is sent:

- an unknown key is an error: a typo must not be silently ignored;
- ``show_secrets`` and ``yes`` are refused: a shared, committed file must not switch off
  redaction or turn one run's authorization into a permanent one;
- ``${NAME}`` is replaced from the environment, and a missing variable is an error rather
  than an empty string;
- a credential written into the file literally is accepted but produces a warning.

The command line overrides the file. Repeatable options (``headers``, ``cookies``,
``exclude``, ``scope_hosts``, ``exclude_hosts``) are combined: the file's entries first,
then the command line's.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path

from .request_options import is_sensitive_header, proxy_credentials


class ConfigError(ValueError):
    """The config file cannot be used; the message says why."""


# config key -> argparse dest. Inverted booleans are handled where the value is converted.
CONFIG_KEYS: dict[str, str] = {
    "targets": "target",
    "targets_file": "targets_file",
    "checks": "checks",
    "fail_on": "fail_on",
    "timeout": "timeout",
    "workers": "workers",
    "parallel": "parallel",
    "rate_limit": "rate_limit",
    "max_requests": "max_requests",
    "max_duration": "max_duration",
    "scope_hosts": "scope_host",
    "exclude": "exclude",
    "exclude_hosts": "exclude_host",
    "default_excludes": "no_default_excludes",
    "tls_probe": "no_tls_probe",
    "api_spec": "api_spec",
    "scan_id_header": "scan_id_header",
    "ca_bundle": "ca_bundle",
    "proxy": "proxy",
    "user_agent": "user_agent",
    "headers": "header",
    "cookies": "cookie",
    "baseline": "baseline",
    "baseline_dir": "baseline_dir",
    "suppressions": "suppressions",
    "output_dir": "output_dir",
    "formats": "formats",
    "json": "json",
    "sarif": "sarif",
    "html": "html",
    "csv": "csv",
    "junit": "junit",
    "color": "no_color",
    "quiet": "quiet",
    "verbose": "verbose",
}

_STR = {"targets_file", "fail_on", "ca_bundle", "proxy", "user_agent", "baseline", "baseline_dir",
        "suppressions", "output_dir", "json", "sarif", "html", "csv", "junit", "api_spec"}  # fmt: skip
_INT = {"timeout", "workers", "parallel", "max_requests"}
_NUMBER = {"rate_limit", "max_duration"}
_BOOL = {"default_excludes", "tls_probe", "scan_id_header", "color", "quiet", "verbose"}
_LIST = {"targets", "checks", "scope_hosts", "exclude", "exclude_hosts", "formats"}
_TABLE = {"headers", "cookies"}
_PATHS = {"targets_file", "ca_bundle", "baseline", "baseline_dir", "suppressions", "output_dir",
          "json", "sarif", "html", "csv", "junit", "api_spec"}  # fmt: skip
# Options that stay a per-run decision on the command line.
_COMMAND_LINE_ONLY = {"show_secrets", "yes", "assume_yes", "i_have_authorization", "config"}

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def load_config(path: str, environ: Mapping[str, str] | None = None) -> tuple[dict, list[str]]:
    """Read and validate a config file. Returns ``(values by config key, warnings)``."""
    environ = os.environ if environ is None else environ
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path!r}: {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"config file {path!r} is not valid TOML: {exc}") from exc

    base = Path(path).resolve().parent
    values: dict = {}
    warnings: list[str] = []
    for key, raw in data.items():
        if key in _COMMAND_LINE_ONLY:
            raise ConfigError(f"{path}: '{key}' cannot be set in a config file; give it on the command line")
        if key not in CONFIG_KEYS:
            raise ConfigError(f"{path}: unknown key '{key}'; known keys: {', '.join(sorted(CONFIG_KEYS))}")
        value = _expand(path, key, _check_type(path, key, raw), environ)
        if key in _PATHS:
            value = str(base / value)
        values[key] = value
        warnings += _literal_credentials(path, key, raw)

    if values.get("quiet") and values.get("verbose"):
        raise ConfigError(f"{path}: 'quiet' and 'verbose' cannot both be true")
    return values, warnings


def _check_type(path: str, key: str, value):
    where = f"{path}: '{key}'"
    if key in _STR and not isinstance(value, str):
        raise ConfigError(f"{where} must be a string")
    if key in _INT and (isinstance(value, bool) or not isinstance(value, int)):
        raise ConfigError(f"{where} must be a whole number")
    if key in _NUMBER and (isinstance(value, bool) or not isinstance(value, int | float)):
        raise ConfigError(f"{where} must be a number")
    if key in _BOOL and not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false")
    if key in _LIST and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
        raise ConfigError(f'{where} must be a list of strings, e.g. {key} = ["a", "b"]')
    if key in _TABLE and not (isinstance(value, dict) and all(isinstance(v, str) for v in value.values())):
        raise ConfigError(f'{where} must be a table of strings, e.g. [{key}] then name = "value"')
    return value


def _expand(path: str, key: str, value, environ: Mapping[str, str]):
    """Replace ``${NAME}`` in every string, recursively. A missing variable is an error."""
    if isinstance(value, str):

        def lookup(match: re.Match) -> str:
            name = match.group(1)
            if name not in environ:
                raise ConfigError(f"{path}: '{key}' uses ${{{name}}}, but {name} is not set in the environment")
            return environ[name]

        return _ENV_REF.sub(lookup, value)
    if isinstance(value, list):
        return [_expand(path, key, item, environ) for item in value]
    if isinstance(value, dict):
        return {name: _expand(path, key, item, environ) for name, item in value.items()}
    return value


def _literal_credentials(path: str, key: str, raw) -> list[str]:
    """Warn about credentials written into the file instead of referenced from the environment."""
    fix = 'reference it from the environment instead, e.g. "Bearer ${SCANNER_TOKEN}"'
    if key == "headers":
        return [
            f"{path}: header '{name}' holds a credential written into the file; {fix}"
            for name, value in raw.items()
            if is_sensitive_header(name) and value and not _ENV_REF.search(value)
        ]
    if key == "cookies":
        return [
            f"{path}: cookie '{name}' is written into the file; reference it with ${{NAME}} from the environment"
            for name, value in raw.items()
            if value and not _ENV_REF.search(value)
        ]
    if key == "proxy":
        creds = proxy_credentials(raw)
        if creds and creds[1] and not _ENV_REF.search(raw):
            return [f"{path}: the proxy password is written into the file; use ${{NAME}} from the environment"]
    return []
