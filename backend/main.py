import asyncio
import ipaddress
import json
import logging
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import torch
from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import metrics as prom
from backend.alerting import SlackNotifier
from backend.config import settings
from backend.db import DefenseEvent, SessionLocal, init_db
from backend.defense import ActiveDefender, SafeModeMiddleware
from backend.ingestion import build_source
from backend.models.ensemble import Ensemble
from backend.pipeline import Pipeline, metric_history, recent_anomalies
from backend.schema import NodeSnapshot
from backend.security import (
    ApiKeyMiddleware,
    BasicAuthMiddleware,
    RateLimitMiddleware,
    client_ip,
)
from training.train import load_db, train

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("nexus")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
HOUSEKEEPING_SECONDS = 15


def recent_defense_events(limit: int) -> list[dict]:
    with SessionLocal() as db:
        rows = db.query(DefenseEvent).order_by(DefenseEvent.ts.desc(), DefenseEvent.id.desc()).limit(limit)
        return [row.as_dict() for row in rows]


def _store_defense_event(event: dict) -> None:
    with SessionLocal() as db:
        db.add(
            DefenseEvent(
                ts=event["ts"],
                type=event["type"],
                mode=event["mode"],
                node_id=event.get("node"),
                ip=event.get("ip"),
                ok=bool(event.get("ok", True)),
                score=event.get("score"),
                detail=str(event.get("detail", ""))[:400],
            )
        )
        db.commit()


async def on_defense_event(event: dict) -> None:
    await asyncio.to_thread(_store_defense_event, event)
    pipeline = getattr(app.state, "pipeline", None)
    if pipeline:
        await pipeline.broadcast({"type": "defense", "status": defender_instance.status(), "event": event})


defender_instance = ActiveDefender(
    critical_score=settings.critical_score,
    mode=settings.defense_mode,
    firewall=settings.defense_firewall,
    block_seconds=settings.defense_block_seconds,
    safe_mode_seconds=settings.defense_safe_mode_seconds,
    allowlist=settings.allowlist,
    on_event=on_defense_event,
)


async def _housekeeping() -> None:
    while True:
        await asyncio.sleep(HOUSEKEEPING_SECONDS)
        try:
            await defender_instance.sweep_expired()
        except Exception:
            log.exception("defense housekeeping failed")

async def _continuous_learning() -> None:
    # Retrain every 24 hours automatically
    while True:
        await asyncio.sleep(86400)
        try:
            log.info("Starting autonomous continuous learning cycle...")
            data = await asyncio.to_thread(load_db)
            if data:
                bundle = await asyncio.to_thread(train, data, 12, 40, 500, 42, "online_auto")
                pipeline = getattr(app.state, "pipeline", None)
                if pipeline:
                    pipeline.ensemble.install_bundle(bundle)
                    await pipeline.broadcast({"type": "retrain_complete", "status": "success"})
                    log.info("Autonomous learning cycle complete. Models updated.")
        except Exception:
            log.exception("Continuous learning failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    torch.set_num_threads(1)

    ensemble = Ensemble(
        weights={
            "iforest": settings.weight_isolation_forest,
            "lstm": settings.weight_lstm_ae,
            "transformer": settings.weight_transformer,
            "vae": settings.weight_vae,
        },
        threshold_override=settings.anomaly_threshold,
        critical_score=settings.critical_score,
    )
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
        defender=defender_instance
    )
    await asyncio.to_thread(pipeline.prime_from_db)
    app.state.pipeline = pipeline

    log.info("ingestion source: %s (every %ss)", source.name, source.interval)
    log.info("active defense: mode=%s firewall=%s", defender_instance.mode, defender_instance.firewall)
    if not settings.ingest_api_key:
        log.warning("INGEST_API_KEY is not set: /api/ingest accepts unauthenticated telemetry")
    task = asyncio.create_task(pipeline.run())
    housekeeping = asyncio.create_task(_housekeeping())
    continuous = asyncio.create_task(_continuous_learning())
    try:
        yield
    finally:
        for background in (task, housekeeping, continuous):
            background.cancel()
        for background in (task, housekeeping, continuous):
            with suppress(asyncio.CancelledError):
                await background
        await defender_instance.shutdown()


app = FastAPI(title="Nexus", version="2.0.0", lifespan=lifespan)

# Middleware order: the last one added is outermost, so requests hit the rate limiter first.
app.add_middleware(SafeModeMiddleware, defender=defender_instance)

if settings.ingest_api_key:
    app.add_middleware(ApiKeyMiddleware, api_key=settings.ingest_api_key)

if settings.dashboard_user and settings.dashboard_password:
    # Agents authenticate with the API key instead of dashboard credentials.
    basic_exempt = ("/healthz", "/api/ingest") if settings.ingest_api_key else ("/healthz",)
    app.add_middleware(
        BasicAuthMiddleware,
        username=settings.dashboard_user,
        password=settings.dashboard_password,
        exempt_paths=basic_exempt,
    )

app.add_middleware(
    RateLimitMiddleware,
    per_minute=settings.rate_limit_per_minute,
    trust_proxy=settings.trust_proxy_headers,
)


def _pipeline() -> Pipeline:
    return app.state.pipeline


class Weights(BaseModel):
    iforest: float = Field(ge=0)
    lstm: float = Field(ge=0)
    transformer: float = Field(ge=0)
    vae: float = Field(ge=0)


class IngestPayload(BaseModel):
    node_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:@-]+$")
    timestamp: float | None = None
    cpu_pct: float = Field(ge=0, le=100)
    memory_pct: float = Field(ge=0, le=100)
    net_kbps: float = Field(ge=0, le=1e9)
    latency_ms: float = Field(ge=0, le=1e7)


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
async def ingest_metrics(payload: IngestPayload, request: Request):
    snap = NodeSnapshot(
        node_id=payload.node_id,
        timestamp=payload.timestamp or time.time(),
        cpu_pct=payload.cpu_pct,
        memory_pct=payload.memory_pct,
        net_kbps=payload.net_kbps,
        latency_ms=payload.latency_ms,
    )
    await _pipeline().handle([snap], source_ip=client_ip(request.scope, settings.trust_proxy_headers))
    return {"status": "ok"}


@app.get("/api/defense")
async def defense_status(limit: int = Query(50, ge=1, le=500)):
    events = await asyncio.to_thread(recent_defense_events, limit)
    return {**defender_instance.status(), "events": events}


@app.post("/api/defense/unblock/{ip}")
async def defense_unblock(ip: str):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(400, "invalid IP address") from exc
    if not await defender_instance.unblock(ip):
        raise HTTPException(404, "address is not blocked")
    return {"status": "ok", "unblocked": ip}


@app.get("/metrics")
async def prometheus_metrics():
    return Response(prom.render(_pipeline(), defender_instance), media_type=prom.CONTENT_TYPE)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    pipeline = _pipeline()
    await ws.accept()
    pipeline.clients.add(ws)
    try:
        history = await asyncio.to_thread(recent_anomalies, 50)
        defense_events = await asyncio.to_thread(recent_defense_events, 20)
        await ws.send_text(
            json.dumps(
                {
                    "type": "snapshot",
                    "nodes": list(pipeline.latest.values()),
                    "anomalies": history,
                    "health": pipeline.health(),
                    "defense_events": defense_events,
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
