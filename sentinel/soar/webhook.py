"""Alert webhook delivery with a JSONL outbox fallback. Never raises."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Optional, Sequence
from urllib.parse import urlparse

import requests

from sentinel import config
from sentinel.config import Settings
from sentinel.models import Alert

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class DispatchResult:
    channel: Literal["webhook", "outbox", "failed"]
    detail: str


def build_payload(alert: Alert, intel: Optional[dict[str, Any]],
                  actions: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "alert": alert.model_dump(mode="json"),
        "intel": intel,
        "actions_taken": list(actions),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class WebhookDispatcher:
    def __init__(self, settings: Optional[Settings] = None, *, url: Optional[str] = None,
                 outbox_path: Optional[str] = None, session: Any = None,
                 backoff_s: float = 0.5) -> None:
        self.settings = s = settings or config.settings
        self.url = s.webhook_url if url is None else url
        self.outbox_path = s.webhook_outbox_file if outbox_path is None else outbox_path
        self._http = session if session is not None else requests
        self._backoff_s = backoff_s
        self._lock = threading.Lock()
        if self.url and urlparse(self.url).scheme not in ("http", "https"):
            logger.error("WEBHOOK_URL must be http(s); falling back to the outbox")
            self.url = ""

    def dispatch(self, alert: Alert, intel: Optional[dict[str, Any]] = None,
                 actions: Sequence[dict[str, Any]] = ()) -> DispatchResult:
        try:
            payload = build_payload(alert, intel, actions)
        except Exception as exc:
            logger.exception("could not build webhook payload for %s", alert.id)
            return DispatchResult("failed", f"payload error: {type(exc).__name__}")
        if self.url:
            error = self._post(payload)
            if error is None:
                return DispatchResult("webhook", "delivered")
            logger.warning("webhook delivery failed (%s); writing to outbox", error)
        return self._write_outbox(payload)

    def _post(self, payload: dict[str, Any]) -> Optional[str]:
        attempts = 1 + max(0, self.settings.webhook_retries)
        error = "unknown"
        for attempt in range(attempts):
            try:
                resp = self._http.post(self.url, json=payload,
                                       timeout=self.settings.webhook_timeout_s)
                if 200 <= resp.status_code < 300:
                    return None
                error = f"HTTP {resp.status_code}"
            except Exception as exc:
                error = type(exc).__name__
            if attempt + 1 < attempts and self._backoff_s > 0:
                time.sleep(min(self._backoff_s * (attempt + 1), 2.0))
        return error

    def _write_outbox(self, payload: dict[str, Any]) -> DispatchResult:
        try:
            line = json.dumps(payload, default=str)
            with self._lock:
                parent = os.path.dirname(os.path.abspath(self.outbox_path))
                os.makedirs(parent, exist_ok=True)
                with open(self.outbox_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            return DispatchResult("outbox", self.outbox_path)
        except Exception as exc:
            logger.exception("could not write webhook outbox %s", self.outbox_path)
            return DispatchResult("failed", f"outbox error: {type(exc).__name__}")
