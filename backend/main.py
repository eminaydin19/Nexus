import asyncio
import json
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import torch
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.alerting import SlackNotifier
from backend.config import settings
from backend.db import init_db
from backend.ingestion import build_source
from backend.schema import NodeSnapshot
from backend.models.ensemble import Ensemble
from backend.pipeline import Pipeline, metric_history, recent_anomalies
from backend.security import BasicAuthMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("nexus")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    torch.set_num_threads(1)

    ensemble = Ensemble(
        weights={
            "iforest": settings.weight_isolation_forest,
            "lstm": settings.weight_lstm_ae,
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
    pipeline = Pipeline(source, ensemble, SlackNotifier(settings.slack_webhook_url, settings.alert_cooldown_seconds))
    await asyncio.to_thread(pipeline.prime_from_db)
    app.state.pipeline = pipeline

    log.info("ingestion source: %s (every %ss)", source.name, source.interval)
    task = asyncio.create_task(pipeline.run())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="Nexus", version="2.0.0", lifespan=lifespan)

if settings.dashboard_user and settings.dashboard_password:
    app.add_middleware(
        BasicAuthMiddleware,
        username=settings.dashboard_user,
        password=settings.dashboard_password,
        exempt_paths=("/healthz",),
    )


def _pipeline() -> Pipeline:
    return app.state.pipeline


class Weights(BaseModel):
    iforest: float = Field(ge=0)
    lstm: float = Field(ge=0)
    vae: float = Field(ge=0)


class InjectRequest(BaseModel):
    node_id: str | None = None
    metric: str | None = None


class IngestPayload(BaseModel):
    node_id: str
    timestamp: float | None = None
    cpu_pct: float
    memory_pct: float
    net_kbps: float
    latency_ms: float


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


@app.post("/api/ingest")
async def ingest_metrics(payload: IngestPayload):
    import time
    snap = NodeSnapshot(
        node_id=payload.node_id,
        timestamp=payload.timestamp or time.time(),
        cpu_pct=payload.cpu_pct,
        memory_pct=payload.memory_pct,
        net_kbps=payload.net_kbps,
        latency_ms=payload.latency_ms,
    )
    await _pipeline().handle([snap])
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    pipeline = _pipeline()
    await ws.accept()
    pipeline.clients.add(ws)
    try:
        history = await asyncio.to_thread(recent_anomalies, 50)
        await ws.send_text(
            json.dumps(
                {
                    "type": "snapshot",
                    "nodes": list(pipeline.latest.values()),
                    "anomalies": history,
                    "health": pipeline.health(),
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
