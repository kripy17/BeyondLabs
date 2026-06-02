from typing import Any, Literal

from pydantic import BaseModel, Field


class ToolRunRequest(BaseModel):
    tool_id: str = Field(..., min_length=2, max_length=80)
    target: str = Field(default="", max_length=500)
    profile: str = Field(default="default", max_length=80)
    confirm_authorization: bool = False
    allow_private: bool = False
    timeout_seconds: int = Field(default=60, ge=5, le=180)
    inputs: dict[str, Any] = Field(default_factory=dict)


class ToolProfile(BaseModel):
    id: str
    label: str
    description: str


class ToolDefinition(BaseModel):
    id: str
    name: str
    group: str
    kind: Literal["cli", "local", "knowledge"]
    purpose: str
    usage_note: str
    badges: list[str] = Field(default_factory=list)
    profiles: list[ToolProfile] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    defender_artifacts: list[str] = Field(default_factory=list)
    detection_ideas: list[str] = Field(default_factory=list)
    mitre_mapping: list[dict[str, str]] = Field(default_factory=list)
    report_actions: list[str] = Field(default_factory=list)
    knowledge: dict[str, Any] = Field(default_factory=dict)
    cli_name: str | None = None
