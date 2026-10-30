"""SentinelSOAR HTTP API (FastAPI).

Run with ``uvicorn sentinel.api:app``. When ``SENTINEL_API_KEY`` is set every
endpoint except ``/health`` needs a matching ``X-API-Key`` header (compared in
constant time; the key is never logged). Request bodies are capped at
``SENTINEL_API_MAX_BODY_BYTES`` before any parsing happens.
"""

from __future__ import annotations

import hmac
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel import config
from sentinel.config import Settings
from sentinel.detection.engine import RULES
from sentinel.net import parse_ip
from sentinel.pipeline import Pipeline
from sentinel.soar.firewall import FirewallError
from sentinel.soar.playbooks import PLAYBOOKS
from sentinel.store import IncidentNotFound

logger = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"
INCIDENT_ID_PATTERN = r"^INC-[0-9a-f]{12}$"
MAX_NOTE_CHARS = 1000

PLAYBOOK_DESCRIPTIONS = {
    "enrich_ip_reputation": "Score the source IP with AbuseIPDB (live, cached or mock).",
    "block_ip_firewall": "Add a TTL'd DROP rule when severity is High+ or intel score is high.",
    "revoke_user_sessions": "Revoke the user's and source IP's sessions (T1078 alerts).",
    "escalate_critical": "Set priority by severity; tag Critical incidents for an analyst.",
    "dispatch_webhook_alert": "Send the JSON alert to the webhook, or the outbox file.",
}

SeverityParam = Literal["Low", "Medium", "High", "Critical"]
StatusParam = Literal["open", "contained", "resolved", "false_positive"]


# ------------------------------------------------------------------ schemas

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IngestRequest(_Strict):
    """Exactly one of ``line`` (single) or ``lines`` (batch)."""

    line: Optional[str] = None
    lines: Optional[list[str]] = None

    @model_validator(mode="after")
    def _exactly_one(self) -> "IngestRequest":
        if (self.line is None) == (self.lines is None):
            raise ValueError("provide exactly one of 'line' or 'lines'")
        return self


class StatusRequest(_Strict):
    status: StatusParam
    note: str = Field("", max_length=MAX_NOTE_CHARS)


class ContainRequest(_Strict):
    note: str = Field("", max_length=MAX_NOTE_CHARS)
    revoke_sessions: bool = True


# --------------------------------------------------------------- middleware

class BodySizeLimitMiddleware:
    """Rejects bodies over ``max_bytes`` with 413, whether declared by
    Content-Length or streamed (chunked). The body is buffered up to the limit and
    then replayed to the app, so nothing downstream ever sees an oversized body."""

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await _send_json(send, 400, {"detail": "invalid Content-Length"})
                    return
                if declared > self.max_bytes:
                    await self._reject(send)
                    return

        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":  # client went away: let the app see it
                pending: Optional[dict] = message
                break
            body = message.get("body", b"")
            size += len(body)
            if size > self.max_bytes:
                await self._reject(send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                pending = None
                break

        replayed = False

        async def replay() -> dict:
            nonlocal replayed
            if not replayed:
                replayed = True
                if pending is not None:
                    return pending
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, send: Any) -> None:
        await _send_json(send, 413, {"detail": f"request body exceeds {self.max_bytes} bytes"})


async def _send_json(send: Any, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


# ------------------------------------------------------------- dependencies

_api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


def require_api_key(request: Request,
                    provided: Optional[str] = Depends(_api_key_header)) -> None:
    expected: str = request.app.state.api_key
    if not expected:
        return
    if provided is None or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="invalid or missing API key",
                            headers={"WWW-Authenticate": API_KEY_HEADER})


def get_pipeline(request: Request) -> Pipeline:
    pipeline: Optional[Pipeline] = request.app.state.pipeline
    if pipeline is None:
        raise HTTPException(status_code=503, detail="pipeline not started")
    return pipeline


IncidentId = Path(..., pattern=INCIDENT_ID_PATTERN)


# ------------------------------------------------------------------- routes

public = APIRouter()
protected = APIRouter(dependencies=[Depends(require_api_key)])


@public.get("/health")
def health(request: Request) -> dict[str, Any]:
    pipeline: Optional[Pipeline] = request.app.state.pipeline
    return {
        "status": "ok" if pipeline is not None else "starting",
        "tailing": bool(pipeline and pipeline.tailing),
        "auth_required": bool(request.app.state.api_key),
    }


@protected.post("/ingest")
def ingest(body: IngestRequest, request: Request,
           pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    s: Settings = request.app.state.settings
    lines = [body.line] if body.line is not None else (body.lines or [])
    if len(lines) > s.ingest_max_lines:
        raise HTTPException(status_code=422,
                            detail=f"at most {s.ingest_max_lines} lines per request")
    too_long = next((i for i, ln in enumerate(lines) if len(ln) > s.ingest_max_line_chars),
                    None)
    if too_long is not None:
        raise HTTPException(status_code=422, detail=(
            f"line {too_long} exceeds {s.ingest_max_line_chars} characters"))
    return pipeline.ingest_batch(lines).to_dict()


@protected.get("/api/metrics")
def metrics(pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    doc = pipeline.store.metrics()
    doc["firewall"] = {"active_rules": len(pipeline.firewall.list_rules()),
                       "real": pipeline.firewall.real}
    doc["intel_mode"] = pipeline.intel.mode
    doc["detector_errors"] = dict(pipeline.engine.errors)
    doc["tailing"] = pipeline.tailing
    return doc


@protected.get("/api/incidents")
def list_incidents(
    severity: Optional[SeverityParam] = None,
    status: Optional[StatusParam] = None,
    limit: int = Query(200, ge=1, le=1000),
    pipeline: Pipeline = Depends(get_pipeline),
) -> dict[str, Any]:
    items = pipeline.store.list_incidents(severity=severity, status=status, limit=limit)
    return {"count": len(items), "incidents": items}


@protected.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str = IncidentId,
                 pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    doc = pipeline.store.get_dict(incident_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return doc


@protected.post("/api/incidents/{incident_id}/contain")
def contain_incident(body: Optional[ContainRequest] = None,
                     incident_id: str = IncidentId,
                     pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    body = body or ContainRequest()
    return pipeline.contain(incident_id, note=body.note,
                            revoke_sessions=body.revoke_sessions)


@protected.post("/api/incidents/{incident_id}/status")
def set_incident_status(body: StatusRequest, incident_id: str = IncidentId,
                        pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    return pipeline.store.set_status(incident_id, body.status, note=body.note).to_dict()


@protected.get("/api/firewall/rules")
def firewall_rules(pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    rules = [r.to_dict() for r in pipeline.firewall.list_rules()]
    return {"count": len(rules), "real": pipeline.firewall.real, "rules": rules}


@protected.delete("/api/firewall/rules/{ip}")
def delete_firewall_rule(ip: str = Path(..., max_length=64),
                         pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    try:
        addr = str(parse_ip(ip))
    except ValueError:
        raise HTTPException(status_code=422, detail="not a valid IP address") from None
    try:
        removed = pipeline.firewall.unblock(addr)
    except FirewallError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    if not removed:
        raise HTTPException(status_code=404, detail=f"no firewall rule for {addr}")
    return {"ip": addr, "removed": True}


@protected.get("/api/rules")
def detection_rules(pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    rules = [{**meta, "mitre_url": _mitre_url(meta["mitre"]),
              "playbooks": list(pipeline.runner.chain_for(meta["id"]))}
             for meta in RULES]
    return {"count": len(rules), "rules": rules}


def _mitre_url(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"


@protected.get("/api/playbooks")
def playbooks(pipeline: Pipeline = Depends(get_pipeline)) -> dict[str, Any]:
    chains = {rule: list(chain) for rule, chain in pipeline.runner.chains.items()}
    items = [{"name": name,
              "description": PLAYBOOK_DESCRIPTIONS.get(name, ""),
              "used_by": sorted(rule for rule, chain in chains.items() if name in chain)}
             for name in PLAYBOOKS]
    return {"playbooks": items, "chains": chains}


# ---------------------------------------------------------------------- app

def create_app(
    pipeline: Optional[Pipeline] = None,
    *,
    settings: Optional[Settings] = None,
    api_key: Optional[str] = None,
    max_body_bytes: Optional[int] = None,
    tail: bool = True,
) -> FastAPI:
    """Build the app. Without ``pipeline`` one is created on startup from settings.
    A pipeline built here is closed on shutdown; an injected one is only stopped
    from tailing (its owner closes it)."""
    s = settings or (pipeline.settings if pipeline is not None else config.settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = app.state.pipeline is None
        if owned:
            app.state.pipeline = Pipeline(s)
        pipe: Pipeline = app.state.pipeline
        if tail and pipe.log_paths:
            pipe.start_tailing()
        try:
            yield
        finally:
            pipe.stop_tailing()
            if owned:
                pipe.close()
                app.state.pipeline = None

    app = FastAPI(title="SentinelSOAR", version="1.0", lifespan=lifespan)
    app.state.pipeline = pipeline
    app.state.settings = s
    app.state.api_key = s.api_key if api_key is None else api_key
    app.add_middleware(BodySizeLimitMiddleware,
                       max_bytes=s.api_max_body_bytes if max_body_bytes is None
                       else max_body_bytes)

    @app.exception_handler(IncidentNotFound)
    async def _not_found(request: Request, exc: IncidentNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": "incident not found"})

    app.include_router(public)
    app.include_router(protected)
    return app


app = create_app()
