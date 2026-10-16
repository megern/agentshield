import re
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(default="", max_length=100000)
    tools: list[str] = Field(default_factory=list, max_length=100)
    allowed_domains: list[str] = Field(default_factory=list, max_length=100)
    confirmation_required: bool = True
    sandboxed: bool = True
    secrets_in_context: bool = False

    @field_validator("allowed_domains", "tools")
    @classmethod
    def normalize_entries(cls, values):
        return [value.strip().lower() for value in values if value.strip()]


RULES = [
    (
        "instruction_override",
        r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions",
        "high",
        "Instruction hierarchy override language",
    ),
    (
        "credential_exfiltration",
        r"(send|upload|exfiltrate|reveal).{0,80}(api.?key|password|secret|token)",
        "high",
        "Possible credential disclosure request",
    ),
    (
        "destructive_command",
        r"(rm\s+-rf|drop\s+table|format\s+[a-z]:)",
        "high",
        "Destructive command pattern",
    ),
    (
        "role_spoofing",
        r"(<\|system\|>|\[system\]|system\s+message:)",
        "medium",
        "System role delimiter in untrusted text",
    ),
]


def analyze(req: ScanRequest):
    findings = []

    def add(code, severity, explanation, evidence):
        findings.append(
            dict(
                code=code, severity=severity, explanation=explanation, evidence=evidence
            )
        )

    for code, pattern, severity, explanation in RULES:
        match = re.search(pattern, req.prompt, re.I | re.S)
        if match:
            add(code, severity, explanation, match.group()[:160])
    dangerous = set(req.tools) & {
        "shell",
        "filesystem_write",
        "browser",
        "http",
        "email",
        "payment",
    }
    if dangerous and not req.confirmation_required:
        add(
            "unconfirmed_actions",
            "high",
            "Side-effecting tools lack confirmation",
            sorted(dangerous),
        )
    if "shell" in req.tools and not req.sandboxed:
        add("unsandboxed_shell", "critical", "Shell execution lacks a sandbox", "shell")
    if set(req.tools) & {"http", "browser"} and not req.allowed_domains:
        add(
            "unrestricted_network",
            "medium",
            "Network tools have no domain allowlist",
            req.allowed_domains,
        )
    if req.secrets_in_context:
        add(
            "context_secrets",
            "high",
            "Secrets in model context can be exposed by generated output",
            True,
        )
    weights = {"medium": 10, "high": 25, "critical": 40}
    score = min(100, sum(weights[f["severity"]] for f in findings))
    return {
        "risk_score": score,
        "findings": findings,
        "rules_checked": len(RULES) + 4,
        "limitations": [
            "Heuristic rules do not prove safety or detect all prompt injection.",
            "Configuration is self-reported; tools are not executed or inspected.",
        ],
    }
