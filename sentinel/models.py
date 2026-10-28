"""Shared data contracts: normalized ``Event`` and detector ``Alert``."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

Source = Literal["ssh", "nginx", "pacs", "vpn"]
Severity = Literal["Low", "Medium", "High", "Critical"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(value: datetime) -> datetime:
    """Naive datetimes are taken to be UTC; aware ones are converted to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Event(BaseModel):
    """A single normalized log record, regardless of where it came from."""

    model_config = ConfigDict(extra="forbid")

    ts: datetime
    source: Source
    event_type: str
    src_ip: str = ""
    user: str = ""
    raw: str
    fields: dict[str, Any] = Field(default_factory=dict)
    # Monotonic clock reading taken when the event was parsed (ingested).
    # Detectors copy it into Alert.detected_at_ns so MTTD can be measured.
    ingested_ns: int = Field(default_factory=time.monotonic_ns)
    # Ground truth for the simulator/benchmark only. Detection logic must never read it.
    label: Optional[str] = None

    @field_validator("ts")
    @classmethod
    def _ts_utc(cls, value: datetime) -> datetime:
        return _to_utc(value)


class Alert(BaseModel):
    """A detector finding about one or more events."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    rule_id: str
    title: str
    mitre_technique: str
    severity: Severity
    src_ip: str = ""
    user: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    detected_at_ns: int

    @field_validator("created_at")
    @classmethod
    def _created_utc(cls, value: datetime) -> datetime:
        return _to_utc(value)
