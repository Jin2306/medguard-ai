"""Request and response models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ComponentMetadata(BaseModel):
    name: str = "patient-records-api"
    version: str = "unspecified"
    language: str = "python"
    component_id: str | None = None


class VerifyRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=100_000)
    scenario_id: str | None = None
    requirements: str | None = None
    policy_version: str | None = None
    component: ComponentMetadata | None = None
    rerun_of: str | None = None


class StageModel(BaseModel):
    id: str
    label: str
    status: str
    detail: str = ""


class FindingModel(BaseModel):
    policy_id: str
    title: str
    severity: str
    source: str
    confirmed: bool
    description: str
    recommendation: str
    line: int | None = None


class TestResultModel(BaseModel):
    id: str
    policy_id: str
    title: str
    mandatory: bool
    outcome: str
    detail: str = ""
    layer: str = "baseline"
    counts_as_evidence: bool = True


class AIAnalysisModel(BaseModel):
    mode: str
    advisory_only: bool = True
    configured: bool = False
    model: str | None = None
    risk_level: str = "UNKNOWN"
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    suggested_tests: list[str] = Field(default_factory=list)
    recommendation: str | None = None
    disclaimer: str = ""
    error: str | None = None


class VerificationRunModel(BaseModel):
    run_id: str
    status: str
    created_at: str
    updated_at: str
    scenario_id: str | None = None
    filename: str
    code: str
    code_sha256: str
    policy_version: str
    policy_sha256: str
    decision: str | None = None
    decision_reason: str = ""
    ai: AIAnalysisModel
    stages: list[StageModel]
    findings: list[FindingModel]
    advisory_findings: list[FindingModel]
    generated_tests: str = ""
    test_plan: list[dict[str, Any]] = Field(default_factory=list)
    test_results: list[TestResultModel] = Field(default_factory=list)
    sandbox: dict[str, Any] = Field(default_factory=dict)
    storage_backend: str
    storage_label: str
    disclaimer: str
    related_memory: list[dict[str, Any]] = Field(default_factory=list)
    memory_retrieval: dict[str, Any] = Field(default_factory=dict)
    adversarial: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(default_factory=dict)
    component: dict[str, Any] = Field(default_factory=dict)
    rerun_of: str | None = None
    reproducibility: str = ""
    requirements_note: str | None = None


class HistoryItem(BaseModel):
    run_id: str
    created_at: str
    scenario_id: str | None = None
    decision: str | None = None
    status: str
    code_sha256: str
    storage_backend: str
    storage_label: str


class HealthResponse(BaseModel):
    status: str
    service: str
    policy_version: str
    disclaimer: str
    meta_ai: dict[str, Any]
    mongodb: dict[str, Any]
    semgrep: dict[str, Any]
    sandbox: dict[str, Any]
