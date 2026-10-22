"""Audit user-supplied execution evidence; no tool invocation or enforcement."""

import ipaddress
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$"


class TracePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    allowed_tools: list[str] = Field(max_length=100)
    allowed_domains: list[str] = Field(default_factory=list, max_length=100)
    confirmation_required: bool = True

    @field_validator("allowed_tools")
    @classmethod
    def tools(cls, values):
        if any(not re.fullmatch(IDENTIFIER, value) for value in values):
            raise ValueError("Tool names need 1–100 letters, digits or _ . : -")
        if len(set(values)) != len(values):
            raise ValueError("Allowed tools must be unique")
        return values

    @field_validator("allowed_domains")
    @classmethod
    def domains(cls, values):
        result = []
        for value in values:
            try:
                normalized = (
                    value.strip().rstrip(".").encode("idna").decode("ascii").lower()
                )
            except UnicodeError as exc:
                raise ValueError("Invalid domain name") from exc
            try:
                ipaddress.ip_address(normalized)
            except ValueError:
                if len(normalized) > 253 or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                    for part in normalized.split(".")
                ):
                    raise ValueError(
                        "Use exact hostnames/IPs, with no URLs, ports or wildcards"
                    )
            if normalized in result:
                raise ValueError("Allowed domains must be unique after normalization")
            result.append(normalized)
        return result


class ApprovalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_id: str = Field(pattern=IDENTIFIER)
    action: Literal["approve"]
    call_id: str = Field(pattern=IDENTIFIER)


class CallEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_id: str = Field(pattern=IDENTIFIER)
    action: Literal["call"]
    call_id: str = Field(pattern=IDENTIFIER)
    tool: str = Field(pattern=IDENTIFIER)
    url: str | None = Field(default=None, max_length=2000)

    @field_validator("url")
    @classmethod
    def http_target(cls, value):
        if value is None:
            return value
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port == 0
            ):
                raise ValueError(
                    "Tool URLs must be absolute HTTP(S) URLs without credentials"
                )
            if any(ord(char) < 33 for char in value):
                raise ValueError(
                    "Tool URLs cannot contain whitespace/control characters"
                )
            TracePolicy.domains([parsed.hostname])
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid HTTP(S) tool URL") from exc
        return value


class TraceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    policy: TracePolicy
    events: list[
        Annotated[ApprovalEvent | CallEvent, Field(discriminator="action")]
    ] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def identifiers(self):
        event_ids = [event.event_id for event in self.events]
        calls = [event.call_id for event in self.events if isinstance(event, CallEvent)]
        approvals = [
            event.call_id for event in self.events if isinstance(event, ApprovalEvent)
        ]
        if len(set(event_ids)) != len(event_ids) or len(set(calls)) != len(calls):
            raise ValueError(
                "Event IDs and call IDs must be unique; an approval cannot be reused by repeating a call ID"
            )
        if any(call not in set(calls) for call in approvals):
            raise ValueError("Approval refers to an unknown call ID")
        if len(set(approvals)) != len(approvals):
            raise ValueError("At most one approval event per exact call ID")
        return self


def audit_trace(request: TraceRequest):
    approvals = {}
    violations = []
    calls = []
    allowed_tools = set(request.policy.allowed_tools)
    allowed_hosts = set(request.policy.allowed_domains)
    for index, event in enumerate(request.events):
        if isinstance(event, ApprovalEvent):
            approvals[event.call_id] = index
            continue
        codes = []
        if event.tool not in allowed_tools:
            codes.append("TOOL_NOT_ALLOWED")
        if request.policy.confirmation_required and event.call_id not in approvals:
            codes.append("MISSING_PRIOR_APPROVAL")
        network_call = event.tool in {"http", "browser"} or event.url is not None
        hostname = None
        if network_call:
            if event.url is None:
                codes.append("MISSING_NETWORK_TARGET")
            else:
                hostname = (
                    urlsplit(event.url)
                    .hostname.rstrip(".")
                    .encode("idna")
                    .decode("ascii")
                    .lower()
                )
                if hostname not in allowed_hosts:
                    codes.append("DOMAIN_NOT_ALLOWED")
        for code in codes:
            violations.append(
                {
                    "code": code,
                    "event_index": index,
                    "event_id": event.event_id,
                    "call_id": event.call_id,
                    "tool": event.tool,
                    "host": hostname,
                }
            )
        calls.append(
            {
                "call_id": event.call_id,
                "event_index": index,
                "tool": event.tool,
                "prior_approval": event.call_id in approvals,
                "host": hostname,
                "violation_codes": codes,
            }
        )
    invalid_calls = sum(bool(call["violation_codes"]) for call in calls)
    return {
        "event_count": len(request.events),
        "call_count": len(calls),
        "approval_count": len(approvals),
        "calls_with_violations": invalid_calls,
        "calls_without_violations": len(calls) - invalid_calls,
        "passed": invalid_calls == 0,
        "violation_count": len(violations),
        "violations": violations,
        "calls": calls,
        "limitations": [
            "This audits supplied trace statements only; no tool is executed and approvals/enforcement are not independently verified.",
            "Approvals authorize only the exact call ID and must precede its one call. Later approvals do not retroactively authorize calls.",
            "Domains are exact normalized hosts: no implicit subdomains, redirects, DNS resolution or wildcard matching. Ports are not restricted by this policy.",
            "Tool names are case-sensitive. http/browser calls require a target URL; any other tool with a URL is also checked against the host allowlist.",
            "Custom tool network behavior cannot be inferred: supply its URL to audit the host; only http/browser require a URL automatically.",
            "A passing trace is not a security certification or evidence that omitted actions did not occur.",
        ],
    }
