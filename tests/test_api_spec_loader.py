"""FR-API-01a..c (decision D9): reading an OpenAPI/Swagger file safely.

A spec is a file somebody else wrote, and the scanner reads it before it has sent a single request.
So the loader is where the attacks go: a YAML file that expands to gigabytes ("billion laughs"), a
document nested a hundred thousand levels deep, a ``$ref`` that points at ``http://169.254.169.254/``
or at ``/etc/passwd`` or at ``../../secret.yaml``. None of that may reach the network, read a file
outside the spec's own directory, hang, or crash: each must be an error that says what was wrong.
"""

from __future__ import annotations

import json
import socket
import time

import pytest

from websec_scanner.api import spec_loader
from websec_scanner.api.spec_loader import SpecError

SECRET = "TOP-SECRET-MARKER-9f3a"  # noqa: S105 - a marker in a file the loader must never read, not a credential


def minimal(**extra):
    return {"openapi": "3.0.3", "info": {"title": "T", "version": "1"}, "paths": {}, **extra}


def write(directory, name, content):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return path


@pytest.fixture
def no_network(monkeypatch):
    """Any attempt to open a connection or resolve a name fails the test."""

    def refuse(*args, **kwargs):
        raise AssertionError("the spec loader used the network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


# --- formats ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["spec.json", "spec.JSON"])
def test_a_json_spec_loads(tmp_path, name):
    assert spec_loader.load_spec(write(tmp_path, name, minimal())).document == minimal()


@pytest.mark.parametrize("name", ["spec.yaml", "spec.yml", "spec.YAML"])
def test_a_yaml_spec_loads(tmp_path, name):
    text = "openapi: 3.0.3\ninfo:\n  title: T\n  version: '1'\npaths: {}\n"
    assert spec_loader.load_spec(write(tmp_path, name, text)).document == minimal()


@pytest.mark.parametrize("name", ["spec.txt", "spec", "spec.py", "spec.json.bak"])
def test_other_extensions_are_refused(tmp_path, name):
    with pytest.raises(SpecError, match="extension"):
        spec_loader.load_spec(write(tmp_path, name, minimal()))


@pytest.mark.parametrize(
    "version",
    ["3.0.0", "3.0.3", "3.1.0", "3.1.1"],
)
def test_the_supported_openapi_versions_are_accepted(tmp_path, version):
    spec = spec_loader.load_spec(write(tmp_path, "s.json", minimal(openapi=version)))
    assert spec.kind == "openapi" and spec.version == version


def test_swagger_2_is_accepted(tmp_path):
    spec = spec_loader.load_spec(write(tmp_path, "s.json", {"swagger": "2.0", "info": {"title": "T", "version": "1"}}))
    assert spec.kind == "swagger" and spec.version == "2.0"


@pytest.mark.parametrize(
    "document, message",
    [
        ({"openapi": "4.0.0"}, "openapi 4.0.0"),
        ({"openapi": "3.2.0"}, "openapi 3.2.0"),
        ({"openapi": "2.0"}, "openapi 2.0"),
        ({"swagger": "1.2"}, "swagger 1.2"),
        ({"info": {"title": "T"}}, "not an OpenAPI"),
        ({"openapi": ["3.0.3"]}, "openapi"),
    ],
)
def test_an_unsupported_or_unrecognised_document_says_so(tmp_path, document, message):
    with pytest.raises(SpecError, match=message):
        spec_loader.load_spec(write(tmp_path, "s.json", document))


@pytest.mark.parametrize(
    "name, content, message",
    [
        ("zero.json", "", "is empty"),  # not "empty.json": the file name is in the message and would match
        ("blank.yaml", "   \n", "is empty"),
        ("list.json", "[1, 2]", "mapping|object"),
        ("scalar.yaml", "just text", "mapping|object"),
        ("broken.json", "{not json", "JSON"),
        ("broken.yaml", "a: [unclosed", "YAML"),
        ("nul.json", '{"openapi": "3.0.3"}\x00', "NUL|null"),
        ("latin1.json", b'{"openapi": "3.0.3", "x": "\xe9"}', "UTF-8"),
    ],
)
def test_a_malformed_file_is_an_error_not_a_crash(tmp_path, name, content, message):
    with pytest.raises(SpecError, match=message):
        spec_loader.load_spec(write(tmp_path, name, content))


def test_a_missing_file_and_a_directory_are_refused(tmp_path):
    with pytest.raises(SpecError, match="cannot read|not a file|does not exist"):
        spec_loader.load_spec(tmp_path / "nope.json")
    with pytest.raises(SpecError, match="not a regular file"):
        spec_loader.load_spec(tmp_path)


def test_a_utf8_byte_order_mark_is_tolerated(tmp_path):
    path = write(tmp_path, "bom.json", b"\xef\xbb\xbf" + json.dumps(minimal()).encode("utf-8"))
    assert spec_loader.load_spec(path).document["openapi"] == "3.0.3"


# --- YAML is read as the OpenAPI spec means it ------------------------------------------------------------


def test_yaml_words_that_are_not_booleans_in_yaml_1_2_stay_strings(tmp_path):
    text = (
        "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\n"
        "x-flags: {yes: 1, no: 2, on: 3, off: 4, y: 5, n: 6, up: true, down: false}\n"
    )
    flags = spec_loader.load_spec(write(tmp_path, "s.yaml", text)).document["x-flags"]
    assert flags == {"yes": 1, "no": 2, "on": 3, "off": 4, "y": 5, "n": 6, "up": True, "down": False}


def test_numeric_keys_such_as_response_codes_become_strings(tmp_path):
    text = "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\nx-codes: {200: ok, 404: missing}\n"
    assert spec_loader.load_spec(write(tmp_path, "s.yaml", text)).document["x-codes"] == {"200": "ok", "404": "missing"}


def test_dates_are_plain_strings(tmp_path):
    text = "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\nx-when: 2024-01-31\n"
    assert spec_loader.load_spec(write(tmp_path, "s.yaml", text)).document["x-when"] == "2024-01-31"


def test_python_object_tags_are_refused_and_run_nothing(tmp_path):
    text = "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\nx-evil: !!python/object/apply:os.getcwd []\n"
    with pytest.raises(SpecError, match="YAML"):
        spec_loader.load_spec(write(tmp_path, "s.yaml", text))
    text = "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\nx-evil: !!python/name:os.system\n"
    with pytest.raises(SpecError, match="YAML"):
        spec_loader.load_spec(write(tmp_path, "t.yaml", text))


@pytest.mark.parametrize(
    "name, text", [("d.json", '{"openapi": "3.0.3", "a": 1, "a": 2}'), ("d.yaml", "openapi: 3.0.3\na: 1\na: 2\n")]
)
def test_a_repeated_key_is_refused_because_parsers_disagree_about_it(tmp_path, name, text):
    with pytest.raises(SpecError, match="repeated|duplicate"):
        spec_loader.load_spec(write(tmp_path, name, text))


# --- limits ---------------------------------------------------------------------------------------------------


def test_a_file_over_the_size_limit_is_refused_before_it_is_parsed(tmp_path):
    assert spec_loader.MAX_FILE_BYTES == 5 * 1024 * 1024
    path = write(tmp_path, "big.json", b"#" * (spec_loader.MAX_FILE_BYTES + 1))
    with pytest.raises(SpecError, match="larger than"):
        spec_loader.load_spec(path)


def test_the_size_limit_is_inclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(spec_loader, "MAX_FILE_BYTES", 400)
    ok = json.dumps(minimal(**{"x-pad": "p" * 280}))
    assert len(ok.encode()) <= 400
    spec_loader.load_spec(write(tmp_path, "ok.json", ok))
    with pytest.raises(SpecError, match="larger than"):
        spec_loader.load_spec(write(tmp_path, "over.json", json.dumps(minimal(**{"x-pad": "p" * 600}))))


BILLION_LAUGHS = (
    "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\n"
    "x-a: &a [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n"
    "x-b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
    "x-c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
    "x-d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
    "x-e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]\n"
    "x-f: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]\n"
    "x-g: &g [*f, *f, *f, *f, *f, *f, *f, *f, *f]\n"
    "x-h: &h [*g, *g, *g, *g, *g, *g, *g, *g, *g]\n"
    "x-i: &i [*h, *h, *h, *h, *h, *h, *h, *h, *h]\n"
)


def test_a_billion_laughs_file_is_stopped_quickly_by_a_budget_not_by_the_file_size(tmp_path):
    path = write(tmp_path, "bomb.yaml", BILLION_LAUGHS)
    assert path.stat().st_size < 1024, "the file is tiny: only an expansion budget can catch it"
    started = time.monotonic()
    with pytest.raises(SpecError, match="alias|expand"):
        spec_loader.load_spec(path)
    assert time.monotonic() - started < 5


def test_an_alias_that_refers_to_itself_is_refused(tmp_path):
    text = "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\nx-loop: &a [*a]\n"
    with pytest.raises(SpecError, match="alias|deep|nest|recurs"):
        spec_loader.load_spec(write(tmp_path, "loop.yaml", text))


def test_ordinary_alias_reuse_is_fine(tmp_path):
    text = (
        "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\n"
        "x-shared: &p {name: limit, in: query}\nx-uses: [*p, *p, *p]\n"
    )
    assert (
        spec_loader.load_spec(write(tmp_path, "ok.yaml", text)).document["x-uses"]
        == [{"name": "limit", "in": "query"}] * 3
    )


def _deep_json() -> str:
    return '{"openapi": "3.0.3", "x": ' + "[" * 100_000 + "]" * 100_000 + "}"


def _deep_yaml_flow() -> str:
    return "openapi: 3.0.3\nx: " + "[" * 5_000 + "]" * 5_000 + "\n"


def _deep_yaml_block() -> str:
    levels = "".join("  " * (i + 1) + "k:\n" for i in range(150))
    return "openapi: 3.0.3\nx:\n" + levels + "  " * 151 + "v: 1\n"


def _deep_json_below_the_recursion_limit() -> str:
    return '{"openapi": "3.0.3", "x": ' + "[" * 200 + "]" * 200 + "}"


DEEP = {  # built inside the test: a 100,000-character parameter would be pytest's test id
    "json-200-levels": ("mid.json", _deep_json_below_the_recursion_limit),
    "json-100000-levels": ("deep.json", _deep_json),
    "yaml-flow-5000-levels": ("deep.yaml", _deep_yaml_flow),
    "yaml-block-150-levels": ("block.yaml", _deep_yaml_block),
}


@pytest.mark.parametrize("case", sorted(DEEP))
def test_very_deep_nesting_is_an_error_not_a_crash(tmp_path, case):
    name, build = DEEP[case]
    text = build()
    with pytest.raises(SpecError, match="deep|nest"):
        spec_loader.load_spec(write(tmp_path, name, text))


def test_nesting_up_to_the_limit_is_allowed(tmp_path):
    levels = spec_loader.MAX_NESTING - 6
    text = json.dumps({"openapi": "3.0.3", "x": json.loads('{"k":' * levels + "1" + "}" * levels)})
    spec_loader.load_spec(write(tmp_path, "ok.json", text))


def test_the_loader_never_touches_the_network(tmp_path, no_network):
    spec_loader.load_spec(write(tmp_path, "a.json", minimal()))
    spec_loader.load_spec(write(tmp_path, "b.yaml", "openapi: 3.0.3\ninfo: {title: T, version: '1'}\npaths: {}\n"))


# --- $ref: what may be followed ---------------------------------------------------------------------------------


def spec_with(directory, **sections):
    return spec_loader.load_spec(write(directory, "spec.json", minimal(**sections)))


def test_an_internal_reference_resolves(tmp_path):
    spec = spec_with(tmp_path, components={"parameters": {"Limit": {"name": "limit", "in": "query"}}})
    value, base = spec.follow({"$ref": "#/components/parameters/Limit"}, spec.path)
    assert value == {"name": "limit", "in": "query"} and base == spec.path


def test_a_chain_of_references_is_followed_to_the_end(tmp_path):
    spec = spec_with(
        tmp_path,
        components={"parameters": {"A": {"$ref": "#/components/parameters/B"}, "B": {"name": "b", "in": "path"}}},
    )
    assert spec.follow({"$ref": "#/components/parameters/A"}, spec.path)[0] == {"name": "b", "in": "path"}


def test_pointer_escapes_and_list_indexes_work(tmp_path):
    spec = spec_with(tmp_path, paths={"/a/b": {"get": {"parameters": [{"name": "x", "in": "query"}]}}})
    value, _ = spec.follow({"$ref": "#/paths/~1a~1b/get/parameters/0"}, spec.path)
    assert value == {"name": "x", "in": "query"}


def test_a_node_without_a_reference_is_returned_as_it_is(tmp_path):
    spec = spec_with(tmp_path)
    node = {"name": "limit", "in": "query"}
    assert spec.follow(node, spec.path) == (node, spec.path)


def test_a_reference_to_a_file_in_the_same_directory_resolves(tmp_path):
    write(tmp_path, "common.yaml", "parameters:\n  Limit: {name: limit, in: query}\n")
    spec = spec_with(tmp_path)
    value, base = spec.follow({"$ref": "common.yaml#/parameters/Limit"}, spec.path)
    assert value == {"name": "limit", "in": "query"} and base == (tmp_path / "common.yaml").resolve()


def test_references_inside_an_included_file_are_relative_to_that_file(tmp_path):
    write(tmp_path, "sub/a.yaml", "p: {$ref: 'b.yaml#/q'}\n")
    write(tmp_path, "sub/b.yaml", "q: {name: deep, in: header}\n")
    spec = spec_with(tmp_path)
    first, base = spec.follow({"$ref": "sub/a.yaml#/p"}, spec.path)
    assert first == {"name": "deep", "in": "header"}
    assert base == (tmp_path / "sub" / "b.yaml").resolve()


def test_a_reference_may_climb_back_up_inside_the_spec_directory(tmp_path):
    write(tmp_path, "shared.json", {"p": {"name": "up", "in": "query"}})
    write(tmp_path, "sub/a.json", {"p": {"$ref": "../shared.json#/p"}})
    spec = spec_with(tmp_path)
    assert spec.follow({"$ref": "sub/a.json#/p"}, spec.path)[0] == {"name": "up", "in": "query"}


FORBIDDEN = [
    "http://169.254.169.254/latest/meta-data/",
    "https://example.com/schema.json",
    "HTTP://example.com/x.json",
    "ftp://example.com/x.json",
    "file:///etc/passwd",
    "//evil.example/x.json",
    "/etc/passwd",
    "/var/secret.yaml",
    "C:\\Windows\\win.ini",
    "C:/Windows/win.ini",
    "\\\\server\\share\\x.yaml",
    "..\\..\\secret.yaml",
    "../../secret.yaml",
    "../secret.yaml",
    "sub/../../secret.yaml",
    "%2e%2e/secret.yaml",
    "..%2fsecret.yaml",
    "secret.yaml%00.json",
    "secret.yaml\x00.json",
]

WRONG_EXTENSION = ["notes.txt", "script.py", "data.xml", "noextension"]


@pytest.mark.parametrize("target", FORBIDDEN)
def test_a_reference_that_leaves_the_spec_directory_or_the_machine_is_refused(tmp_path, target, no_network):
    outside = write(tmp_path, "secret.yaml", f"p: {SECRET}\n")
    root = tmp_path / "spec"
    spec = spec_loader.load_spec(write(root, "spec.json", minimal()))
    assert outside.exists()
    with pytest.raises(SpecError) as caught:
        spec.follow({"$ref": target}, spec.path)
    assert SECRET not in str(caught.value), "the refused file must never be read"
    assert "not allowed" in str(caught.value), str(caught.value)


@pytest.mark.parametrize("target", WRONG_EXTENSION)
def test_only_json_and_yaml_files_are_followed(tmp_path, target):
    write(tmp_path, target, "p: 1\n")
    spec = spec_with(tmp_path)
    with pytest.raises(SpecError, match="extension"):
        spec.follow({"$ref": target}, spec.path)


def test_a_symlink_that_points_outside_the_directory_is_refused(tmp_path):
    outside = write(tmp_path, "secret.yaml", f"p: {SECRET}\n")
    root = tmp_path / "spec"
    spec = spec_loader.load_spec(write(root, "spec.json", minimal()))
    try:
        (root / "link.yaml").symlink_to(outside)
    except OSError:
        pytest.skip("this account cannot create symlinks")
    with pytest.raises(SpecError, match="not allowed") as caught:
        spec.follow({"$ref": "link.yaml#/p"}, spec.path)
    assert SECRET not in str(caught.value)


def test_a_reference_to_a_directory_is_refused(tmp_path):
    (tmp_path / "folder.json").mkdir()
    spec = spec_with(tmp_path)
    with pytest.raises(SpecError, match="not a regular file"):
        spec.follow({"$ref": "folder.json#/p"}, spec.path)


def test_a_reference_cycle_is_an_error(tmp_path):
    spec = spec_with(
        tmp_path,
        components={
            "parameters": {"A": {"$ref": "#/components/parameters/B"}, "B": {"$ref": "#/components/parameters/A"}}
        },
    )
    with pytest.raises(SpecError, match="circular"):
        spec.follow({"$ref": "#/components/parameters/A"}, spec.path)


def test_a_reference_to_itself_is_an_error(tmp_path):
    spec = spec_with(tmp_path, components={"parameters": {"A": {"$ref": "#/components/parameters/A"}}})
    with pytest.raises(SpecError, match="circular"):
        spec.follow({"$ref": "#/components/parameters/A"}, spec.path)


def test_a_chain_longer_than_the_depth_limit_is_an_error(tmp_path):
    chain = {f"P{i}": {"$ref": f"#/components/parameters/P{i + 1}"} for i in range(spec_loader.MAX_REF_DEPTH + 8)}
    chain[f"P{spec_loader.MAX_REF_DEPTH + 8}"] = {"name": "end", "in": "query"}
    spec = spec_with(tmp_path, components={"parameters": chain})
    with pytest.raises(SpecError, match="too deep|too long"):
        spec.follow({"$ref": "#/components/parameters/P0"}, spec.path)


def test_a_chain_exactly_at_the_depth_limit_is_fine(tmp_path):
    n = spec_loader.MAX_REF_DEPTH - 1
    chain = {f"P{i}": {"$ref": f"#/components/parameters/P{i + 1}"} for i in range(n)}
    chain[f"P{n}"] = {"name": "end", "in": "query"}
    spec = spec_with(tmp_path, components={"parameters": chain})
    assert spec.follow({"$ref": "#/components/parameters/P0"}, spec.path)[0]["name"] == "end"


def test_the_number_of_references_followed_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(spec_loader, "MAX_REFS", 5)
    spec = spec_with(tmp_path, components={"parameters": {"A": {"name": "a", "in": "query"}}})
    for _ in range(5):
        spec.follow({"$ref": "#/components/parameters/A"}, spec.path)
    with pytest.raises(SpecError, match="too many"):
        spec.follow({"$ref": "#/components/parameters/A"}, spec.path)


def test_the_spec_and_its_included_files_share_one_size_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(spec_loader, "MAX_TOTAL_BYTES", 600)
    for name in ("a", "b", "c"):
        write(tmp_path, f"{name}.json", {"p": {"name": name, "pad": "x" * 150}})  # about 190 bytes each
    spec = spec_with(tmp_path)  # about 75 bytes
    spec.follow({"$ref": "a.json#/p"}, spec.path)
    spec.follow({"$ref": "b.json#/p"}, spec.path)
    with pytest.raises(SpecError, match="together larger"):
        spec.follow({"$ref": "c.json#/p"}, spec.path)


def test_the_number_of_included_files_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(spec_loader, "MAX_FILES", 2)
    for name in ("a", "b", "c"):
        write(tmp_path, f"{name}.json", {"p": {"name": name, "in": "query"}})
    spec = spec_with(tmp_path)
    spec.follow({"$ref": "a.json#/p"}, spec.path)
    spec.follow({"$ref": "b.json#/p"}, spec.path)
    with pytest.raises(SpecError, match="too many files"):
        spec.follow({"$ref": "c.json#/p"}, spec.path)


@pytest.mark.parametrize(
    "ref, message",
    [
        ("#/components/parameters/Missing", "does not exist"),
        ("#/components/parameters/Limit/name/deeper", "does not exist"),
        ("#/paths/0", "does not exist"),
        ("missing.json#/p", "cannot read|does not exist|not a file"),
        ("#", "whole document|root"),
    ],
)
def test_a_reference_to_nothing_is_an_error_that_names_it(tmp_path, ref, message):
    spec = spec_with(tmp_path, components={"parameters": {"Limit": {"name": "limit", "in": "query"}}})
    with pytest.raises(SpecError, match=message):
        spec.follow({"$ref": ref}, spec.path)


@pytest.mark.parametrize("value", [None, 5, ["#/a"], {"x": 1}, ""])
def test_a_reference_that_is_not_a_string_is_an_error(tmp_path, value):
    spec = spec_with(tmp_path)
    with pytest.raises(SpecError, match=r"\$ref"):
        spec.follow({"$ref": value}, spec.path)


def test_an_included_file_obeys_the_same_limits_as_the_spec(tmp_path, monkeypatch):
    write(tmp_path, "big.yaml", "p: " + "x" * 600 + "\n")
    monkeypatch.setattr(spec_loader, "MAX_FILE_BYTES", 400)
    spec = spec_with(tmp_path)
    with pytest.raises(SpecError, match="larger than"):
        spec.follow({"$ref": "big.yaml#/p"}, spec.path)
    write(tmp_path, "bomb.yaml", BILLION_LAUGHS.split("paths: {}\n")[1])
    monkeypatch.setattr(spec_loader, "MAX_FILE_BYTES", 5 * 1024 * 1024)
    with pytest.raises(SpecError, match="alias|expand"):
        spec.follow({"$ref": "bomb.yaml#/x-i"}, spec.path)
