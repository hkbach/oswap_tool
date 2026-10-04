"""FR-API-01d (decision D9): what the scanner takes from a spec.

An inventory lists the servers, the endpoints (method, path, parameters, which security schemes
apply) and the security schemes. It is built from the spec alone: nothing is requested from any
server it names, and nothing is taken from examples, defaults or descriptions, which is where a
spec keeps sample secrets.
"""

from __future__ import annotations

import json

import pytest

from websec_scanner.api import inventory, spec_loader
from websec_scanner.api.spec_loader import SpecError


def build(tmp_path, document, name="spec.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return inventory.build_inventory(path)


def oas3(**sections):
    return {"openapi": "3.0.3", "info": {"title": "Pets", "version": "2.1"}, **sections}


def by_key(inv):
    return {(e.method, e.path): e for e in inv.endpoints}


# --- OpenAPI 3.x ---------------------------------------------------------------------------------------------


def test_the_basics_of_a_small_spec(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            servers=[{"url": "https://api.example.com/v1"}],
            paths={"/pets": {"get": {"operationId": "listPets", "parameters": [{"name": "limit", "in": "query"}]}}},
        ),
    )
    assert (inv.source, inv.kind, inv.version, inv.title) == ("spec.json", "openapi", "3.0.3", "Pets")
    assert inv.servers == ("https://api.example.com/v1",)
    (endpoint,) = inv.endpoints
    assert (endpoint.method, endpoint.path, endpoint.operation_id) == ("GET", "/pets", "listPets")
    assert [(p.name, p.location, p.required) for p in endpoint.parameters] == [("limit", "query", False)]


def test_only_http_methods_become_endpoints_and_extensions_are_ignored(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            paths={
                "/a": {
                    "summary": "not an operation",
                    "description": "nor this",
                    "parameters": [],
                    "servers": [{"url": "/x"}],
                    "x-internal": {"get": {}},
                    "get": {},
                    "put": {},
                    "post": {},
                    "delete": {},
                    "options": {},
                    "head": {},
                    "patch": {},
                    "trace": {},
                },
                "x-hidden": {"get": {}},
            }
        ),
    )
    assert sorted(e.method for e in inv.endpoints) == [
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
        "TRACE",
    ]
    assert {e.path for e in inv.endpoints} == {"/a"}


def test_endpoints_are_listed_in_a_stable_order_whatever_the_file_order(tmp_path):
    forward = build(tmp_path, oas3(paths={"/b": {"post": {}, "get": {}}, "/a": {"get": {}}}), "f.json")
    backward = build(tmp_path, oas3(paths={"/a": {"get": {}}, "/b": {"get": {}, "post": {}}}), "g.json")
    assert [(e.path, e.method) for e in forward.endpoints] == [("/a", "GET"), ("/b", "GET"), ("/b", "POST")]
    assert [(e.path, e.method) for e in forward.endpoints] == [(e.path, e.method) for e in backward.endpoints]


def test_path_level_and_operation_level_parameters_are_merged_with_the_operation_winning(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            paths={
                "/pets/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True}, {"name": "trace", "in": "header"}],
                    "get": {
                        "parameters": [
                            {"name": "trace", "in": "header", "required": True},
                            {"name": "q", "in": "query"},
                        ]
                    },
                }
            }
        ),
    )
    (endpoint,) = inv.endpoints
    assert sorted((p.name, p.location, p.required) for p in endpoint.parameters) == [
        ("id", "path", True),
        ("q", "query", False),
        ("trace", "header", True),
    ]


def test_parameters_given_by_reference_are_resolved(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            paths={"/a": {"get": {"parameters": [{"$ref": "#/components/parameters/Limit"}]}}},
            components={"parameters": {"Limit": {"name": "limit", "in": "query", "required": True}}},
        ),
    )
    assert [(p.name, p.location, p.required) for p in inv.endpoints[0].parameters] == [("limit", "query", True)]


def test_a_path_item_given_by_reference_to_another_file_is_followed(tmp_path):
    (tmp_path / "pets.json").write_text(
        json.dumps({"get": {"operationId": "fromFile", "parameters": [{"$ref": "params.json#/Limit"}]}})
    )
    (tmp_path / "params.json").write_text(json.dumps({"Limit": {"name": "limit", "in": "query"}}))
    inv = build(tmp_path, oas3(paths={"/pets": {"$ref": "pets.json"}}))
    (endpoint,) = inv.endpoints
    assert endpoint.operation_id == "fromFile" and [p.name for p in endpoint.parameters] == ["limit"]


def test_schemas_examples_and_defaults_are_never_read(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            paths={
                "/login": {
                    "post": {
                        "parameters": [
                            {
                                "name": "token",
                                "in": "query",
                                "example": "SECRET-EXAMPLE",
                                "schema": {"default": "SECRET-DEFAULT"},
                            }
                        ],
                        "requestBody": {"content": {"application/json": {"example": {"password": "SECRET-BODY"}}}},
                        "description": "SECRET-DESCRIPTION",
                    }
                }
            }
        ),
    )
    assert "SECRET" not in json.dumps(inv.to_dict())


def test_a_bad_schema_reference_does_not_matter_because_schemas_are_not_resolved(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            paths={
                "/a": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query", "schema": {"$ref": "http://169.254.169.254/x"}}]
                    }
                }
            }
        ),
    )
    assert inv.endpoints[0].parameters[0].name == "q"


def test_a_server_url_has_its_variables_filled_with_their_defaults(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            servers=[
                {
                    "url": "https://{env}.example.com:{port}/v1",
                    "variables": {"env": {"default": "api"}, "port": {"default": "8443"}},
                },
                {"url": "/relative"},
                {"url": "https://{unknown}.example.com"},
            ]
        ),
    )
    assert inv.servers == ("https://api.example.com:8443/v1", "/relative", "https://{unknown}.example.com")


def test_a_spec_without_servers_has_the_default_one(tmp_path):
    assert build(tmp_path, oas3()).servers == ("/",)


def test_security_schemes_are_described_without_their_secrets(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            components={
                "securitySchemes": {
                    "key": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                    "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                    "basic": {"type": "http", "scheme": "basic"},
                    "oauth": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "https://a",
                                "tokenUrl": "https://t",
                                "scopes": {},
                            },
                            "clientCredentials": {"tokenUrl": "https://t", "scopes": {}},
                        },
                    },
                    "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://o/.well-known"},
                }
            }
        ),
    )
    described = {s.name: (s.type, s.detail) for s in inv.security_schemes}
    assert described == {
        "basic": ("http", "basic"),
        "bearer": ("http", "bearer"),
        "key": ("apiKey", "header X-API-Key"),
        "oauth": ("oauth2", "authorizationCode, clientCredentials"),
        "oidc": ("openIdConnect", ""),
    }


def test_global_security_applies_unless_an_operation_overrides_it(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            security=[{"key": []}],
            paths={
                "/inherits": {"get": {}},
                "/own": {"get": {"security": [{"bearer": []}, {"basic": []}]}},
                "/open": {"get": {"security": []}},
            },
            components={
                "securitySchemes": {
                    "key": {"type": "apiKey", "in": "header", "name": "K"},
                    "bearer": {"type": "http", "scheme": "bearer"},
                    "basic": {"type": "http", "scheme": "basic"},
                }
            },
        ),
    )
    found = by_key(inv)
    assert found[("GET", "/inherits")].security == ("key",)
    assert found[("GET", "/own")].security == ("basic", "bearer")
    assert found[("GET", "/open")].security == ()


def test_deprecated_is_recorded(tmp_path):
    inv = build(tmp_path, oas3(paths={"/old": {"get": {"deprecated": True}}, "/new": {"get": {}}}))
    assert {e.path: e.deprecated for e in inv.endpoints} == {"/old": True, "/new": False}


def test_openapi_3_1_without_paths_has_no_endpoints_and_ignores_webhooks(tmp_path):
    inv = build(
        tmp_path, {"openapi": "3.1.0", "info": {"title": "W", "version": "1"}, "webhooks": {"hook": {"post": {}}}}
    )
    assert inv.endpoints == () and inv.version == "3.1.0"


# --- Swagger 2.0 ---------------------------------------------------------------------------------------------------


SWAGGER = {
    "swagger": "2.0",
    "info": {"title": "Legacy", "version": "1"},
    "host": "api.example.com",
    "basePath": "/v2",
    "schemes": ["https", "http"],
    "parameters": {"Limit": {"name": "limit", "in": "query", "required": False, "type": "integer"}},
    "securityDefinitions": {
        "basic": {"type": "basic"},
        "key": {"type": "apiKey", "in": "query", "name": "api_key"},
        "oauth": {"type": "oauth2", "flow": "implicit", "authorizationUrl": "https://a", "scopes": {}},
    },
    "security": [{"key": []}],
    "paths": {
        "/pets": {
            "parameters": [{"$ref": "#/parameters/Limit"}],
            "get": {"parameters": [{"name": "body", "in": "body", "required": True}]},
            "post": {"security": []},
        }
    },
}


def test_swagger_servers_are_built_from_host_base_path_and_schemes(tmp_path):
    assert build(tmp_path, SWAGGER).servers == ("https://api.example.com/v2", "http://api.example.com/v2")


def test_swagger_without_a_host_has_only_its_base_path(tmp_path):
    document = {key: value for key, value in SWAGGER.items() if key != "host"}
    assert build(tmp_path, document).servers == ("/v2",)


def test_swagger_parameters_security_and_schemes(tmp_path):
    inv = build(tmp_path, SWAGGER)
    assert (inv.kind, inv.version) == ("swagger", "2.0")
    found = by_key(inv)
    assert sorted((p.name, p.location) for p in found[("GET", "/pets")].parameters) == [
        ("body", "body"),
        ("limit", "query"),
    ]
    assert found[("GET", "/pets")].security == ("key",)
    assert found[("POST", "/pets")].security == ()
    assert {s.name: (s.type, s.detail) for s in inv.security_schemes} == {
        "basic": ("basic", ""),
        "key": ("apiKey", "query api_key"),
        "oauth": ("oauth2", "implicit"),
    }


# --- limits and errors ---------------------------------------------------------------------------------------------


def test_too_many_endpoints_is_an_error_not_a_silent_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "MAX_ENDPOINTS", 5)
    five = {f"/p{i}": {"get": {}} for i in range(5)}
    assert len(build(tmp_path, oas3(paths=five), "five.json").endpoints) == 5
    six = {f"/p{i}": {"get": {}} for i in range(6)}
    with pytest.raises(SpecError, match="too many endpoints"):
        build(tmp_path, oas3(paths=six), "six.json")


def test_too_many_parameters_on_one_operation_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "MAX_PARAMETERS", 3)
    params = [{"name": f"p{i}", "in": "query"} for i in range(4)]
    with pytest.raises(SpecError, match="too many parameters"):
        build(tmp_path, oas3(paths={"/a": {"get": {"parameters": params}}}))


@pytest.mark.parametrize(
    "document, message",
    [
        (oas3(paths=[]), "paths"),
        (oas3(paths={"/a": []}), "/a"),
        (oas3(paths={"/a": {"get": []}}), "GET /a"),
        (oas3(paths={"/a": {"get": {"parameters": {}}}}), "parameters"),
        (oas3(paths={"/a": {"get": {"parameters": [{"in": "query"}]}}}), "name"),
        (oas3(paths={"/a": {"get": {"parameters": [{"name": "q"}]}}}), "no 'in'"),
        (oas3(paths={"/a": {"get": {"parameters": [{"name": "q", "in": "nowhere"}]}}}), "nowhere"),
        (oas3(servers="https://x"), "servers"),
        (oas3(components={"securitySchemes": []}), "securitySchemes"),
        (oas3(security="key"), "security"),
    ],
)
def test_a_malformed_spec_is_an_error_naming_the_place(tmp_path, document, message):
    with pytest.raises(SpecError, match=message):
        build(tmp_path, document)


def test_a_reference_that_cannot_be_followed_surfaces_as_a_spec_error(tmp_path):
    document = oas3(paths={"/a": {"get": {"parameters": [{"$ref": "http://169.254.169.254/latest"}]}}})
    with pytest.raises(SpecError, match="not allowed"):
        build(tmp_path, document)


# --- the shape that goes into the JSON report -------------------------------------------------------------------


def test_to_dict_is_the_documented_shape(tmp_path):
    inv = build(
        tmp_path,
        oas3(
            servers=[{"url": "https://api.example.com"}],
            security=[{"key": []}],
            paths={
                "/pets": {
                    "get": {
                        "operationId": "list",
                        "deprecated": True,
                        "parameters": [{"name": "limit", "in": "query", "required": True}],
                    }
                }
            },
            components={"securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
        ),
    )
    assert inv.to_dict() == {
        "source": "spec.json",
        "format": "openapi",
        "version": "3.0.3",
        "title": "Pets",
        "servers": ["https://api.example.com"],
        "security_schemes": [{"name": "key", "type": "apiKey", "detail": "header X-API-Key"}],
        "endpoint_count": 1,
        "endpoints": [
            {
                "method": "GET",
                "path": "/pets",
                "operation_id": "list",
                "parameters": [{"name": "limit", "in": "query", "required": True}],
                "security": ["key"],
                "deprecated": True,
            }
        ],
    }


def test_to_dict_can_redact_every_text_that_came_from_the_spec(tmp_path):
    inv = build(
        tmp_path,
        {
            **oas3(servers=[{"url": "https://user:pw@api.example.com"}]),
            "info": {"title": "T https://u:p@h/", "version": "1"},
        },
    )
    shown = inv.to_dict(redact=lambda text: text.replace("pw", "<r>").replace("u:p", "<r>"))
    assert "pw" not in json.dumps(shown) and "u:p" not in json.dumps(shown)
    assert "pw" in json.dumps(inv.to_dict()), "without a redactor the text is untouched"


def test_the_source_is_the_file_name_never_a_local_path(tmp_path):
    inv = build(tmp_path, oas3(), "my-api.json")
    assert inv.source == "my-api.json" and str(tmp_path) not in json.dumps(inv.to_dict())


def test_the_loader_limits_apply_when_building_an_inventory(tmp_path, monkeypatch):
    monkeypatch.setattr(spec_loader, "MAX_FILE_BYTES", 50)
    with pytest.raises(SpecError, match="larger than"):
        build(tmp_path, oas3(paths={"/a": {"get": {}}}))
