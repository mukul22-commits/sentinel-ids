"""Response policy schemas for automated response orchestration (Phase 6)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import RESPONSE_ACTION_TARGET_TYPES, RESPONSE_ACTION_TYPES, RULE_SEVERITIES


class PolicyAction(BaseModel):
    action_type: str
    target_type: str
    target_value: str = Field(min_length=1, max_length=512)

    @field_validator("action_type")
    @classmethod
    def _validate_action_type(cls, value: str) -> str:
        if value not in RESPONSE_ACTION_TYPES:
            raise ValueError(f"action_type must be one of {RESPONSE_ACTION_TYPES}")
        return value

    @field_validator("target_type")
    @classmethod
    def _validate_target_type(cls, value: str) -> str:
        if value not in RESPONSE_ACTION_TARGET_TYPES:
            raise ValueError(f"target_type must be one of {RESPONSE_ACTION_TARGET_TYPES}")
        return value


class PolicyConditions(BaseModel):
    severity: list[str] = []
    detectors: list[str] = []
    categories: list[str] = []
    min_risk_score: float = Field(default=0, ge=0, le=100)

    @field_validator("severity")
    @classmethod
    def _validate_severities(cls, values: list[str]) -> list[str]:
        for value in values:
            if value not in RULE_SEVERITIES:
                raise ValueError(f"severity must be one of {RULE_SEVERITIES}")
        return values


class ResponsePolicyBase(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    conditions: PolicyConditions = PolicyConditions()
    actions: list[PolicyAction] = Field(min_length=1, max_length=20)
    cooldown_seconds: int = Field(default=3600, ge=0)


class ResponsePolicyCreate(ResponsePolicyBase):
    pass


class ResponsePolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    enabled: bool | None = None
    conditions: PolicyConditions | None = None
    actions: list[PolicyAction] | None = Field(default=None, min_length=1, max_length=20)
    cooldown_seconds: int | None = Field(default=None, ge=0)


class ResponsePolicyRead(ResponsePolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_by: int | None
    created_at: datetime
    updated_at: datetime


class ResponsePolicyList(BaseModel):
    items: list[ResponsePolicyRead]
    total: int
    page: int
    page_size: int
