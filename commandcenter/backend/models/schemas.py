"""Pydantic models for command center API responses."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class StatusResponse(BaseModel):
    engaged: bool = False
    targets: List[str] = Field(default_factory=list)
    target_count: int = 0
    active_sessions: List[str] = Field(default_factory=list)
    stolen_data: int = 0
    stealth_active: bool = False
    warlog_entries: int = 0
    attack_log: int = 0
    beacons: List[str] = Field(default_factory=list)
    beacon_count: int = 0
    c2_status: Dict[str, Any] = Field(default_factory=dict)
    c2_channels: int = 0
    c2_active_channels: int = 0
    c2_recorded_channels: int = 0
    c2_beacons: int = 0
    c2_tasks: int = 0
    boneyard_items: int = 0
    degraded: List[str] = Field(default_factory=list)


class TargetSummary(BaseModel):
    id: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    status: Optional[str] = None
    is_critical: Optional[bool] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    created_at: Optional[str] = None
    epoch: Optional[float] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class TargetDetail(BaseModel):
    host: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    attack_paths: Dict[str, Any] = Field(default_factory=dict)


class FindingItem(BaseModel):
    id: Optional[str] = None
    category: Optional[str] = None
    title: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = None
    timestamp: Optional[str] = None
    epoch: Optional[float] = None
    host_id: Optional[str] = None


class BoneyardSummary(BaseModel):
    total_items: int = 0
    categories: Dict[str, int] = Field(default_factory=dict)
    storage_dir: Optional[str] = None
    encrypted: bool = False
    schema_version: Optional[str] = None
    error: Optional[str] = None


class IntegrityResponse(BaseModel):
    verified: bool = True
    total_rows_checked: int = 0
    broken_hmacs: List[Dict[str, Any]] = Field(default_factory=list)
    broken_chain_links: List[Dict[str, Any]] = Field(default_factory=list)
    orphaned_audit_entries: List[Dict[str, Any]] = Field(default_factory=list)
    table_counts: Dict[str, int] = Field(default_factory=dict)
    audit_chain_length: int = 0


class AttackGraph(BaseModel):
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    outcomes: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None


class ChannelStatus(BaseModel):
    channel_id: str
    status: str = "unknown"
    endpoint: Optional[str] = None
    beacon_count: int = 0
    task_count: int = 0
    fail_count: int = 0
    established_at: float = 0.0
    last_beacon: float = 0.0
    target: Optional[str] = None


class ChannelHealth(BaseModel):
    healthy: bool = False
    channel_id: Optional[str] = None
    status: Optional[str] = None
    fail_count: int = 0
    reason: Optional[str] = None


class TaskItem(BaseModel):
    task_id: str
    channel_id: str
    command: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    received_at: float = 0.0


class WarLogEntry(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[str] = None
    epoch: Optional[float] = None
    level: Optional[str] = None
    module: Optional[str] = None
    message: Optional[str] = None
    target: Optional[str] = None
    event_type: Optional[str] = None
    span_id: Optional[str] = None
    trace_id: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    extra: Dict[str, Any] = Field(default_factory=dict)


class WarLogSummary(BaseModel):
    session_id: Optional[str] = None
    total_entries: int = 0
    duration_seconds: float = 0.0
    level_counts: Dict[str, int] = Field(default_factory=dict)
    log_file: Optional[str] = None


class ReportGenerateRequest(BaseModel):
    format: str = "json"
    operator: str = "THE VOID"
    engagement_name: str = "Engagement Report"
    output_path: Optional[str] = None


class ReportGenerateResponse(BaseModel):
    format: str
    content: str
    path: Optional[str] = None


class ExportResponse(BaseModel):
    path: str
    entries: int = 0


class ErrorResponse(BaseModel):
    detail: str
    degraded: bool = False
