import asyncio
import ipaddress
import json
import logging
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal

import torch
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from backend import metrics as prom
from backend.agents import MODES, require_agent, router as agents_router, touch
from backend.commands import ack, pending
from backend.alerting import SlackNotifier
from backend.config import settings
from backend.db import ActiveBlock, Agent, SecurityEvent, SessionLocal, init_db
from backend.ingestion import build_source
from backend.models.ensemble import Ensemble
from backend.pipeline import Pipeline, metric_history, recent_anomalies
from backend.schema import NodeSnapshot
from backend.security import (
    BasicAuthMiddleware,
    OriginCheckMiddleware,
    RateLimitMiddleware,
)
from training.train import NotEnoughDataError, load_db, train

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("nexus")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def recent_events(limit: int, node=None, rule=None, action=None, simulated=None) -> list[dict]:
    with SessionLocal() as db:
        query = db.query(SecurityEvent)
        for column, value in (
            (SecurityEvent.node_id, node),
            (SecurityEvent.rule, rule),
            (SecurityEvent.action, action),
            (SecurityEvent.simulated, simulated),
        ):
            if value is not None:
                query = query.filter(column == value)
        rows = query.order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(limit)
        return [row.as_dict() for row in rows]


RETRAIN_CHECK_SECONDS = 3600
RETRAIN_INTERVAL_SECONDS = 86400
_now = time.monotonic


async def _continuous_learning() -> None:
    # Hourly attempts while no model exists; with a model, at most one attempt (even a failed one) per day.
    last_attempt: float | None = None
    while True:
        await asyncio.sleep(RETRAIN_CHECK_SECONDS)
        pipeline = getattr(app.state, "pipeline", None)
        if pipeline is None:
            continue
        if pipeline.ensemble.ready:
            if last_attempt is None:
                last_attempt = _now()
                continue
            if _now() - last_attempt < RETRAIN_INTERVAL_SECONDS:
                continue
        last_attempt = _now()
        try:
            log.info("Starting autonomous continuous learning cycle...")
            data = await asyncio.to_thread(load_db)
            if not data:
                continue
            bundle = await asyncio.to_thread(train, data, 12, 40, 500, 42, "online_auto")
            pipeline.ensemble.install_bundle(bundle)
            await pipeline.broadcast({"type": "retrain_complete", "status": "success"})
            log.info("Autonomous learning cycle complete. Models updated.")
        except NotEnoughDataError as e:
            log.info("Continuous learning skipped: %s", e)
        except Exception:
            log.exception("Continuous learning failed")


def build_ensemble(cfg) -> Ensemble:
    return Ensemble(
        weights={
            "iforest": cfg.weight_isolation_forest,
            "lstm": cfg.weight_lstm_ae,
            "vae": cfg.weight_vae,
            "transformer": cfg.weight_transformer,
        },
        threshold_override=cfg.anomaly_threshold,
        critical_score=cfg.critical_score,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.require_dashboard_credentials()
    init_db()
    torch.set_num_threads(1)

    ensemble = build_ensemble(settings)
    try:
        if not ensemble.load(settings.bundle_path):
            log.warning("no trained model at %s, running in learning mode", settings.bundle_path)
    except Exception:
        log.exception("could not load model bundle, running in learning mode")

    source = build_source(settings)
    pipeline = Pipeline(
        source, 
        ensemble, 
        SlackNotifier(settings.slack_webhook_url, settings.alert_cooldown_seconds),
    )
    await asyncio.to_thread(pipeline.prime_from_db)
    app.state.pipeline = pipeline

    log.info("ingestion source: %s (every %ss)", source.name, source.interval)
    task = asyncio.create_task(pipeline.run())
    continuous = asyncio.create_task(_continuous_learning())
    try:
        yield
    finally:
        for background in (task, continuous):
            background.cancel()
        for background in (task, continuous):
            with suppress(asyncio.CancelledError):
                await background


app = FastAPI(title="Nexus", version="2.0.0", lifespan=lifespan)

# Middleware order: the last one added is outermost, so requests hit the rate limiter first.


def basic_exempt_paths() -> tuple[str, ...]:
    # These authenticate with an agent key or enroll token instead of dashboard credentials.
    return ("/healthz", "/api/ingest", "/api/agents/enroll", "/install-agent.sh")


app.add_middleware(
    BasicAuthMiddleware,
    username=settings.dashboard_user,
    password=settings.dashboard_password,
    exempt_paths=basic_exempt_paths(),
)
app.add_middleware(OriginCheckMiddleware, trust_proxy=settings.trust_proxy_headers)

app.add_middleware(
    RateLimitMiddleware,
    per_minute=settings.rate_limit_per_minute,
    trust_proxy=settings.trust_proxy_headers,
)

app.include_router(agents_router)


def _pipeline() -> Pipeline:
    return app.state.pipeline


class Weights(BaseModel):
    iforest: float = Field(ge=0)
    lstm: float = Field(ge=0)
    vae: float = Field(ge=0)
    transformer: float = Field(default=0.30, ge=0)


MAX_CLOCK_SKEW_SECONDS = 86400
MAX_JSON_FIELD_BYTES = 8192


def _sane_ts(ts: float | None, now: float) -> float:
    # A wrong agent clock must not write rows far in the past or future, where retention and charts would lose them.
    return now if ts is None or abs(ts - now) > MAX_CLOCK_SKEW_SECONDS else ts


def _canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


class SecurityEventIn(BaseModel):
    rule: str = Field(min_length=1, max_length=64)
    ip: str
    action: Literal["block_port", "block_all", "rate_limit", "alert"]
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list, max_length=16)
    ttl: int = Field(default=0, ge=0, le=86400)
    evidence: str = ""
    simulated: bool = False
    ok: bool = True
    ts: float | None = None

    _valid_ip = field_validator("ip")(_canonical_ip)

    @field_validator("evidence", mode="before")
    @classmethod
    def _truncate(cls, value):
        return value[:500] if isinstance(value, str) else value


class BlockIn(BaseModel):
    ip: str
    rule: str = Field(max_length=64)
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list, max_length=16)
    until: float
    simulated: bool = False

    _valid_ip = field_validator("ip")(_canonical_ip)


class IngestPayload(BaseModel):
    timestamp: float | None = None
    cpu_pct: float = Field(ge=0, le=100)
    memory_pct: float = Field(ge=0, le=100)
    net_kbps: float = Field(ge=0, le=1e9)
    latency_ms: float = Field(ge=0, le=1e7)
    events: list[SecurityEventIn] = Field(default_factory=list, max_length=500)
    active_blocks: list[BlockIn] = Field(default_factory=list, max_length=1000)
    acked_commands: list[int] = Field(default_factory=list, max_length=500)
    version: str | None = Field(default=None, max_length=32)
    capabilities: dict | None = None
    config: dict | None = None

    @field_validator("capabilities", "config")
    @classmethod
    def _small(cls, value):
        if value is not None and len(json.dumps(value)) > MAX_JSON_FIELD_BYTES:
            raise ValueError("too large")
        return value


def _apply_ingest(node_id: str, payload: IngestPayload, now: float) -> tuple[list[dict], list[dict]]:
    """Persist what the agent reported and return (stored events, commands still pending)."""
    with SessionLocal() as db:
        # Ack first so a command acknowledged in this request is never sent back.
        ack(db, node_id, payload.acked_commands)
        agent = db.get(Agent, node_id)
        if payload.version is not None:
            agent.version = payload.version
        if payload.capabilities is not None:
            agent.capabilities = payload.capabilities
        if payload.config is not None:
            agent.config = payload.config
            if payload.config.get("max_mode") in MODES:
                agent.max_mode = payload.config["max_mode"]
        touch(db, agent)

        db.query(ActiveBlock).filter(ActiveBlock.node_id == node_id).delete(synchronize_session=False)
        db.add_all(ActiveBlock(node_id=node_id, **b.model_dump()) for b in payload.active_blocks)
        rows = [
            SecurityEvent(node_id=node_id, **{**e.model_dump(), "ts": _sane_ts(e.ts, now)}) for e in payload.events
        ]
        db.add_all(rows)
        db.commit()
        return [r.as_dict() for r in rows], pending(db, node_id)


def _slack_worthy(event: dict) -> bool:
    if event["action"] == "alert":
        return event["rule"] == "distributed_flood"
    return not event["simulated"]


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/health")
async def health():
    return _pipeline().health()


@app.get("/api/nodes")
async def nodes():
    return {"nodes": list(_pipeline().latest.values())}


@app.get("/api/metrics/{node_id}")
def metrics(node_id: str, minutes: int = Query(60, ge=1, le=60 * 24 * 30), points: int = Query(600, ge=10, le=5000)):
    return {"node": node_id, "points": metric_history(node_id, minutes, points)}


@app.get("/api/anomalies")
def anomalies(limit: int = Query(50, ge=1, le=500), node: str | None = None):
    return {"anomalies": recent_anomalies(limit, node)}


@app.get("/api/model")
async def model_info():
    return _pipeline().ensemble.info()


@app.post("/api/weights")
async def set_weights(body: Weights):
    try:
        _pipeline().ensemble.set_weights(body.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"weights": _pipeline().ensemble.weights}


@app.post("/api/retrain")
async def trigger_retrain():
    try:
        data = await asyncio.to_thread(load_db)
        if not data:
            raise HTTPException(400, "Not enough data to retrain.")
        bundle = await asyncio.to_thread(train, data, 12, 40, 500, 42, "online_manual")
        _pipeline().ensemble.install_bundle(bundle)
        await _pipeline().broadcast({"type": "retrain_complete", "status": "success"})
        return {"status": "ok", "message": "Models successfully retrained and hot-swapped."}
    except Exception as e:
        log.exception("Manual retrain failed")
        raise HTTPException(500, f"Retrain failed: {e!s}")


@app.post("/api/ingest")
async def ingest_metrics(payload: IngestPayload, agent: Agent = Depends(require_agent)):
    node_id, now = agent.node_id, time.time()
    events, commands = await asyncio.to_thread(_apply_ingest, node_id, payload, now)
    snap = NodeSnapshot(
        node_id=node_id,
        timestamp=_sane_ts(payload.timestamp, now),
        cpu_pct=payload.cpu_pct,
        memory_pct=payload.memory_pct,
        net_kbps=payload.net_kbps,
        latency_ms=payload.latency_ms,
    )
    pipeline = _pipeline()
    await pipeline.handle([snap])
    if events:
        await pipeline.broadcast({"type": "events", "node": node_id, "events": events})
        for event in filter(_slack_worthy, events):
            await pipeline.notifier.notify_event(event)
    return {"status": "ok", "commands": commands, "acked": bool(payload.acked_commands)}


@app.get("/api/events")
async def events(
    node: str | None = None,
    rule: str | None = None,
    action: str | None = None,
    simulated: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    return {"events": await asyncio.to_thread(recent_events, limit, node, rule, action, simulated)}


def _all_blocks() -> list[dict]:
    with SessionLocal() as db:
        return [b.as_dict() for b in db.query(ActiveBlock).order_by(ActiveBlock.node_id, ActiveBlock.until)]


@app.get("/api/blocks")
async def blocks():
    return {"blocks": await asyncio.to_thread(_all_blocks)}


@app.get("/metrics")
async def prometheus_metrics():
    return Response(prom.render(_pipeline()), media_type=prom.CONTENT_TYPE)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    pipeline = _pipeline()
    await ws.accept()
    pipeline.clients.add(ws)
    try:
        history = await asyncio.to_thread(recent_anomalies, 50)
        recent = await asyncio.to_thread(recent_events, 20)
        await ws.send_text(
            json.dumps(
                {
                    "type": "snapshot",
                    "nodes": list(pipeline.latest.values()),
                    "anomalies": history,
                    "health": pipeline.health(),
                    "events": recent,
                }
            )
        )
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        pipeline.clients.discard(ws)


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
