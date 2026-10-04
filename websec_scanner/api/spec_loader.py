"""Read an OpenAPI 3.0/3.1 or Swagger 2.0 file safely (FR-API-01a..c, decision D9).

A spec is a file somebody else wrote, and it is read before the scanner has sent a single request,
so this is the module an attack would aim at. What it refuses, and why:

* **Anything but a file on this machine.** No URL is ever fetched, no name is ever resolved: the
  module does not import ``socket``. A ``$ref`` to ``http://169.254.169.254/`` is an error, never
  a request.
* **A file that is too big or too deep.** At most ``MAX_FILE_BYTES`` per file, nested at most
  ``MAX_NESTING`` levels. The size limit alone is not enough: a YAML file of a few hundred bytes
  can use aliases to stand for billions of values ("billion laughs"), so the document is also
  walked with a budget of ``MAX_EXPANDED_NODES`` values, counting every alias each time it is used.
* **YAML that can run code.** Only the safe loader is used, so tags such as ``!!python/object``
  are an error.
* **Ambiguity.** A key that appears twice is refused (parsers disagree about which one wins), and
  ``yes``/``no``/``on``/``off`` are strings as in YAML 1.2, which is what OpenAPI specifies.
* **A ``$ref`` that leaves the spec.** Only ``#/pointer`` inside a file, or a relative path to a
  ``.json``/``.yaml``/``.yml`` file that stays inside the directory of the spec after symlinks
  and ``..`` are resolved. Absolute paths, drive letters, UNC paths, backslashes, percent
  escapes, URLs, cycles, chains deeper than ``MAX_REF_DEPTH``, more than ``MAX_REFS``
  references or ``MAX_FILES`` included files are all errors.

Everything is an error with a message that names the file and the problem; nothing here raises
anything else, hangs, or reads outside the directory of the spec.
"""

from __future__ import annotations

import datetime
import json
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import unquote

import yaml

MAX_FILE_BYTES = 5 * 1024 * 1024  # per file
MAX_TOTAL_BYTES = 10 * 1024 * 1024  # the spec and every file it includes
MAX_NESTING = 64
MAX_EXPANDED_NODES = 500_000
MAX_REF_DEPTH = 32
MAX_REFS = 10_000
MAX_FILES = 20  # files pulled in through $ref, not counting the spec itself

_FORMATS = {".json": "JSON", ".yaml": "YAML", ".yml": "YAML"}
_OPENAPI_3 = re.compile(r"3\.[01](\.\d+)?")


class SpecError(ValueError):
    """The spec cannot be read, or breaks a limit. The message says which file and what."""


def _fail(message: str) -> NoReturn:
    raise SpecError(message)


def _show(text: object, limit: int = 100) -> str:
    """A bounded, quoted rendering of text that came from the file, for an error message."""
    shown = repr(str(text))
    return shown if len(shown) <= limit else shown[: limit - 1] + "…'"


# --- YAML, read the way OpenAPI means it ---

_YamlBase = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # the C loader is ~5x faster on a 5 MB file


class _SpecYamlLoader(_YamlBase):  # type: ignore[misc, valid-type]
    """Safe loader that refuses repeated keys and reads yes/no/on/off as strings (YAML 1.2)."""

    def construct_mapping(self, node, deep=False):
        seen: set = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=True)
            if isinstance(key, (list, dict, set)):
                continue  # not hashable; the base class reports it
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"found a repeated key {_show(key)}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


_SpecYamlLoader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_SpecYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def _check_node_budget(root) -> None:
    """Walk the composed YAML graph counting every use of every alias, before anything is built.

    ``&a [x, x, x]`` used nine times, nested nine levels, is a few hundred bytes that mean 9**9
    values; PyYAML builds it by sharing, but anything that walks it afterwards (a ``$ref``
    resolver, a JSON dump) would not. The depth limit also stops a node that contains itself.
    """
    remaining = MAX_EXPANDED_NODES
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        remaining -= 1
        if remaining < 0:
            _fail(
                f"expands to more than {MAX_EXPANDED_NODES:,} values: YAML aliases can make a tiny file "
                "stand for billions of values, so this one was refused"
            )
        if depth > MAX_NESTING:
            _fail(f"is nested more than {MAX_NESTING} levels deep (or refers to itself through an alias)")
        if isinstance(node, yaml.SequenceNode):
            stack.extend((child, depth + 1) for child in node.value)
        elif isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                stack.append((key, depth + 1))
                stack.append((value, depth + 1))


def _parse_yaml(text: str) -> Any:
    loader = _SpecYamlLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            _fail("is empty")
        _check_node_budget(node)
        return loader.construct_document(node)
    except yaml.YAMLError as exc:
        reason = str(exc).replace("\n", " ")
        _fail(f"is not valid YAML (or uses a tag that is not allowed): {reason[:200]}")
    finally:
        loader.dispose()


# --- JSON ---


class _Repeated(ValueError):
    pass


def _json_object(pairs):
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise _Repeated(f"found a repeated key {_show(key)}")
        seen[key] = value
    return seen


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_json_object)
    except RecursionError:
        _fail("is nested too deeply to read")
    except _Repeated as exc:
        _fail(f"has a repeated key: {exc}")
    except json.JSONDecodeError as exc:
        _fail(f"is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})")
    except ValueError as exc:  # for instance an integer with thousands of digits
        _fail(f"is not valid JSON: {str(exc)[:200]}")


# --- turning what was parsed into plain JSON-compatible data ---


def _plain(value: Any, depth: int = 1) -> Any:
    """Keys become strings (a response code ``200`` is a YAML integer), dates become ISO text."""
    if depth > MAX_NESTING:
        _fail(f"is nested more than {MAX_NESTING} levels deep")
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key).lower() if isinstance(key, bool) else str(key)
            if name in result:
                _fail(f"has a repeated key {_show(name)} (numeric and text keys count as the same)")
            result[name] = _plain(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_plain(item, depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_plain(item, depth + 1) for item in value)
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


# --- one file ---


@dataclass
class _Budget:
    """What one spec, with all the files it includes, may still consume."""

    bytes_left: int = field(default_factory=lambda: MAX_TOTAL_BYTES)  # read when the spec is loaded, not at import
    refs: int = 0
    included: int = 0


def _load_file(path: Path, budget: _Budget) -> Any:
    name = path.name
    suffix = path.suffix.lower()
    if suffix not in _FORMATS:
        _fail(f"{name}: has an unsupported extension {suffix or '(none)'!r}; use .json, .yaml or .yml")
    try:
        status = path.stat()
    except FileNotFoundError:
        _fail(f"{name}: does not exist")
    except OSError as exc:
        _fail(f"{name}: cannot read it: {exc.strerror or exc}")
    if not stat.S_ISREG(status.st_mode):
        _fail(f"{name}: is not a regular file")
    if status.st_size > MAX_FILE_BYTES:
        _fail(f"{name}: is larger than {MAX_FILE_BYTES:,} bytes")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        _fail(f"{name}: cannot read it: {exc.strerror or exc}")
    if len(raw) > MAX_FILE_BYTES:
        _fail(f"{name}: is larger than {MAX_FILE_BYTES:,} bytes")
    budget.bytes_left -= len(raw)
    if budget.bytes_left < 0:
        _fail(f"{name}: the spec and the files it includes are together larger than {MAX_TOTAL_BYTES:,} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        _fail(f"{name}: is not valid UTF-8")
    if "\x00" in text:
        _fail(f"{name}: contains a NUL byte")
    if not text.strip():
        _fail(f"{name}: is empty")
    try:
        parsed = _parse_yaml(text) if _FORMATS[suffix] == "YAML" else _parse_json(text)
        return _plain(parsed)
    except SpecError as exc:
        message = str(exc)
        raise SpecError(f"{name}: {message}") from None
    except RecursionError:
        _fail(f"{name}: is nested too deeply to read")


# --- the spec and its $refs ---


@dataclass
class Spec:
    """A loaded spec: its document, and a way to follow ``$ref`` values that stays inside its directory."""

    path: Path  # resolved: the file the operator named
    document: dict
    kind: str  # "openapi" or "swagger"
    version: str
    _budget: _Budget = field(default_factory=_Budget, repr=False)
    _files: dict[Path, Any] = field(default_factory=dict, repr=False)

    @property
    def _root(self) -> Path:
        return self.path.parent

    def follow(self, node: Any, base: Path) -> tuple[Any, Path]:
        """Resolve ``node`` if it is ``{"$ref": ...}``, repeatedly, returning the value and the file it is in.

        ``base`` is the file that contains ``node``: a relative reference is relative to it.
        Anything that is not a ``$ref`` object is returned unchanged.
        """
        seen: set[tuple[Path, str]] = set()
        hops = 0
        while isinstance(node, dict) and "$ref" in node:
            hops += 1
            if hops > MAX_REF_DEPTH:
                _fail(f"a chain of $ref values is too deep (more than {MAX_REF_DEPTH} in a row)")
            self._budget.refs += 1
            if self._budget.refs > MAX_REFS:
                _fail(f"too many $ref values to follow (limit {MAX_REFS:,})")
            target, pointer = self._locate(node["$ref"], base)
            if (target, pointer) in seen:
                _fail(f"circular $ref: {_show(node['$ref'])} leads back to itself")
            seen.add((target, pointer))
            node, base = self._walk(target, pointer, node["$ref"]), target
        return node, base

    def _locate(self, ref: Any, base: Path) -> tuple[Path, str]:
        if not isinstance(ref, str) or not ref.strip():
            _fail(f"a $ref must be a non-empty string, got {_show(ref)}")
        text = ref.strip()
        file_part, _, fragment = text.partition("#")
        if not file_part:
            if not fragment:
                _fail(f"$ref {_show(text)} points at the whole document: name something inside it")
            return base, fragment
        self._check_reference_path(text, file_part)
        resolved = (base.parent / file_part).resolve()
        if not resolved.is_relative_to(self._root):
            _fail(f"$ref {_show(text)} is not allowed: it leaves the directory of the spec")
        return resolved, fragment

    @staticmethod
    def _check_reference_path(text: str, file_part: str) -> None:
        def refuse(reason: str) -> NoReturn:
            _fail(f"$ref {_show(text)} is not allowed: {reason}")

        if "\x00" in text:
            refuse("it contains a NUL byte")
        if "://" in file_part or file_part.startswith("//"):
            refuse("only #/pointers and relative file paths are followed, never URLs")
        if file_part.startswith("/") or re.match(r"^[A-Za-z]:", file_part):
            refuse("absolute paths are not followed")
        if "\\" in file_part:
            refuse("backslashes are not allowed in a path")
        if "%" in file_part:
            refuse("percent-escapes are not allowed in a path")
        if Path(file_part).suffix.lower() not in _FORMATS:
            _fail(f"$ref {_show(text)} has an unsupported extension; only .json, .yaml and .yml files are followed")

    def _document(self, file: Path) -> Any:
        if file in self._files:
            return self._files[file]
        if self._budget.included >= MAX_FILES:
            _fail(f"the spec includes too many files through $ref (limit {MAX_FILES})")
        self._budget.included += 1
        self._files[file] = _load_file(file, self._budget)
        return self._files[file]

    def _walk(self, file: Path, pointer: str, ref: str) -> Any:
        current = self._document(file)
        if not pointer:
            return current
        if not pointer.startswith("/"):
            _fail(f"$ref {_show(ref)}: the part after # must be a JSON pointer starting with /")
        for raw in pointer.split("/")[1:]:
            part = unquote(raw).replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                _fail(f"$ref {_show(ref)} does not exist: nothing at {_show(part)}")
        return current


def load_spec(path: str | Path) -> Spec:
    """Load and validate the top level of a spec file; raises SpecError for anything wrong."""
    given = Path(path)
    if given.exists() and not given.is_file():
        _fail(f"{given.name or given}: is not a regular file")
    budget = _Budget()
    resolved = given.resolve()
    document = _load_file(resolved, budget)
    if not isinstance(document, dict):
        _fail(f"{resolved.name}: the top level must be a mapping (an object), not {type(document).__name__}")
    if "openapi" in document:
        version = str(document["openapi"])
        if not _OPENAPI_3.fullmatch(version):
            _fail(f"{resolved.name}: openapi {version} is not supported (supported: 3.0.x, 3.1.x and Swagger 2.0)")
        kind = "openapi"
    elif "swagger" in document:
        version = str(document["swagger"])
        if version != "2.0":
            _fail(f"{resolved.name}: swagger {version} is not supported (supported: 3.0.x, 3.1.x and Swagger 2.0)")
        kind = "swagger"
    else:
        _fail(f"{resolved.name}: is not an OpenAPI or Swagger document (it has no 'openapi' or 'swagger' key)")
    spec = Spec(resolved, document, kind, version, budget)
    spec._files[resolved] = document
    return spec
