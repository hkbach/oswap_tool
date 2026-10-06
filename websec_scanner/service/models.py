"""Request and response bodies of the API (decision D12). They are also the contract: ``docs/openapi.yaml`` is made
from them, so what is written here is what agencies are told.

Every request body forbids unknown fields (a typo or an option that is not there is an error, not a silent no-op),
and none of them can carry a credential.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..redact import SENSITIVE_PARAM_WORDS

_EXTERNAL_REF = r"^[A-Za-z0-9._:-]{1,128}$"
_METADATA_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_METADATA_KEYS = 20
MAX_METADATA_TEXT = 256

MetadataValue = str | int | float | bool


def _check_metadata(value: dict[str, MetadataValue]) -> dict[str, MetadataValue]:
    if len(value) > MAX_METADATA_KEYS:
        raise ValueError(f"at most {MAX_METADATA_KEYS} keys")
    for key, item in value.items():
        if not _METADATA_KEY.match(key):
            raise ValueError("keys use letters, digits, '_', '.' and '-' (1 to 64 characters)")
        if any(word in key.lower() for word in SENSITIVE_PARAM_WORDS):
            raise ValueError("a key that looks like a credential is not accepted: do not store secrets here")
        if isinstance(item, str) and len(item) > MAX_METADATA_TEXT:
            raise ValueError(f"text values have at most {MAX_METADATA_TEXT} characters")
    return value


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ClientCreate(_Body):
    display_name: Annotated[str, Field(min_length=1, max_length=200, description="Name shown to your own staff.")]
    external_ref: Annotated[
        str | None,
        Field(
            default=None,
            pattern=_EXTERNAL_REF,
            description="Your own reference for this client, unique among your active clients. Fixed once set.",
        ),
    ]
    metadata: Annotated[
        dict[str, MetadataValue],
        Field(default_factory=dict, description="Free labels (text, numbers, true/false). Never put secrets here."),
    ]

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, MetadataValue]) -> dict[str, MetadataValue]:
        return _check_metadata(value)


class ClientUpdate(_Body):
    display_name: Annotated[str | None, Field(default=None, min_length=1, max_length=200)]
    metadata: Annotated[
        dict[str, MetadataValue] | None,
        Field(default=None, description="Replaces the labels when given (send {} to clear them)."),
    ]

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, MetadataValue] | None) -> dict[str, MetadataValue] | None:
        return None if value is None else _check_metadata(value)

    @model_validator(mode="after")
    def _something_to_change(self) -> ClientUpdate:
        if self.display_name is None and self.metadata is None:
            raise ValueError("send display_name, metadata, or both")
        return self


class Client(BaseModel):
    client_id: Annotated[str, Field(description="Made by the service, e.g. cli_01j9z8k2m4q7r5t6v8w0x1y2z3.")]
    display_name: str
    external_ref: str | None
    metadata: dict[str, MetadataValue]
    created_at: Annotated[str, Field(description="UTC, ISO 8601, milliseconds.")]
    updated_at: str


class ClientList(BaseModel):
    items: list[Client]
    next_cursor: Annotated[
        str | None, Field(description="Pass it as `cursor` to get the next page; null when there is no more.")
    ]


class CheckGroup(BaseModel):
    id: str
    title: str
    description: str


class CrawlLimits(BaseModel):
    max_depth: int
    max_pages: int
    max_duration: float
    respect_robots: Annotated[bool, Field(description="Always true: a crawl follows robots.txt.")]


class Options(BaseModel):
    """What a scan request can ask for, so a front end can draw the same form as the demo page."""

    api_version: str
    scanner_version: str
    report_schema_version: str
    check_groups: list[CheckGroup]
    crawl: CrawlLimits


class Problem(BaseModel):
    """RFC 9457 problem details; this is the shape of every error."""

    type: Annotated[str, Field(description="urn:websec:problem:<code>")]
    title: str
    status: int
    detail: str
    code: Annotated[str, Field(description="Stable, machine-readable. Branch on this, not on the text.")]
    request_id: Annotated[str, Field(description="Quote it when you ask for support.")]
    errors: Annotated[list[dict[str, Any]] | None, Field(default=None, description="Field problems of a 422.")]


class Health(BaseModel):
    status: str
    service_version: str


# --- scans (phase 2) -----------------------------------------------------------------------------------------

ScanStatus = Literal["queued", "running", "completed", "failed"]
SCAN_ID_PATTERN = r"^scn_[0-9a-hjkmnp-tv-z]{26}$"
CLIENT_ID_PATTERN = r"^cli_[0-9a-hjkmnp-tv-z]{26}$"
IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9._:-]{1,64}$"


class Attestation(_Body):
    """The agency's statement that it may have this target scanned. It is kept with the scan, and it is the agency's:
    TECHVIFY supplies the scanner and the API, the agency vouches for its own clients."""

    confirmed: Annotated[
        bool,
        Field(
            strict=True, description="Must be true: you confirm that you are authorized to have this target scanned."
        ),
    ]
    statement_version: Annotated[
        str,
        Field(min_length=1, max_length=16, description="The version of the statement you are confirming, e.g. `v1`."),
    ]

    @field_validator("confirmed")
    @classmethod
    def _must_be_true(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("must be true")
        return value


class ScanCreate(_Body):
    client_id: Annotated[str, Field(max_length=64, description="One of your clients (`cli_...`).")]
    target: Annotated[
        str,
        Field(
            min_length=1,
            max_length=2048,
            description="An http(s):// URL or a host name, with no user name or password. Public addresses only.",
        ),
    ]
    checks: Annotated[
        list[str] | None,
        Field(
            default=None,
            min_length=1,
            max_length=16,
            description="Check group ids from `GET /v1/options`. Omit it to run every group.",
        ),
    ]
    crawl: Annotated[
        bool,
        Field(
            default=False,
            strict=True,
            description="Also follow the links of the page on the same origin and check each page (operator's limits).",
        ),
    ]
    attestation: Attestation


class ScanGate(BaseModel):
    fail_on: str
    failed: Annotated[bool, Field(description="At least one finding at or above `fail_on`.")]
    incomplete: Annotated[
        bool, Field(description="The scan could not look at everything (for example the home page was unreachable).")
    ]


class ScanSummary(BaseModel):
    findings: int
    severity: Annotated[dict[str, int], Field(description="Findings per severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.")]
    gate: ScanGate
    pages_scanned: int


class ScanError(BaseModel):
    code: Annotated[
        str, Field(description="`scan_error` (it broke inside the service) or `interrupted` (the service stopped).")
    ]
    detail: str


class Scan(BaseModel):
    scan_id: str
    client_id: str
    target: Annotated[str, Field(description="As you sent it, with anything that looks like a secret masked.")]
    status: ScanStatus
    checks: list[str]
    crawl: bool
    created_at: str
    started_at: str | None
    finished_at: str | None
    summary: Annotated[ScanSummary | None, Field(description="Present once the scan is completed.")]
    error: Annotated[ScanError | None, Field(description="Present when the scan failed.")]
    report_available: Annotated[
        bool, Field(description="True once `GET /v1/scans/{scan_id}/report` returns the report.")
    ]


class ScanList(BaseModel):
    items: list[Scan]
    next_cursor: Annotated[
        str | None, Field(description="Pass it as `cursor` to get the next page; null when there is no more.")
    ]
