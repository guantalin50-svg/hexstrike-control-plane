from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Decision(str, Enum):
    ALLOW = "allow"
    APPROVAL = "require_approval"
    DENY = "deny"


class JobStatus(str, Enum):
    READY = "ready"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class JobRequest(BaseModel):
    tool: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=2048)
    arguments: dict[str, Any] = Field(default_factory=dict)
    justification: str = Field(min_length=3, max_length=1000)
    dry_run: bool = False

    @field_validator("tool")
    @classmethod
    def normalize_tool(cls, value: str) -> str:
        return value.strip().lower().replace("_", "-")

    @model_validator(mode="after")
    def reject_target_smuggling(self) -> "JobRequest":
        reserved = {"target", "targets", "url", "host", "domain", "ip", "network"}
        collisions = reserved.intersection(key.lower() for key in self.arguments)
        if collisions:
            names = ", ".join(sorted(collisions))
            raise ValueError(f"target fields belong in target, not arguments: {names}")
        return self


class EvaluationRequest(BaseModel):
    tool: str
    target: str

    @field_validator("tool")
    @classmethod
    def normalize_tool(cls, value: str) -> str:
        return value.strip().lower().replace("_", "-")


class PolicyEvaluation(BaseModel):
    decision: Decision
    normalized_target: str
    risk: str
    reasons: list[str]


class ApprovalRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class JobRecord(BaseModel):
    id: str
    created_at: str
    updated_at: str
    tool: str
    target: str
    arguments: dict[str, Any]
    justification: str
    requester: str
    dry_run: bool
    status: JobStatus
    decision: Decision
    policy_reasons: list[str]
    approved_by: str | None = None
    approval_reason: str | None = None
    result: Any | None = None
    error: str | None = None


class AuditRecord(BaseModel):
    sequence: int
    timestamp: str
    actor: str
    action: str
    object_type: str
    object_id: str
    details: dict[str, Any]
    previous_hash: str
    event_hash: str

