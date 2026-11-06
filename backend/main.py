import asyncio
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import tarfile
import time
from contextlib import asynccontextmanager, suppress
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

import torch
from fastapi import Depends, FastAPI, HTTPException, Query, Response
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
from backend.panel import router as panel_router
from backend.pipeline import Pipeline, metric_history, recent_anomalies
from backend.schema import NodeSnapshot
from backend.security import (
    BasicAuthMiddleware,
    OriginCheckMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from training.train import NotEnoughDataError, load_db, train

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("nexus")

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"
AGENT_FILE_SUFFIXES = {".py", ".json", ".txt"}
AGENT_EXCLUDED_DIRS = {"__pycache__", "tests"}


def _ships_with_agent(path: Path) -> bool:
    parts = path.relative_to(ROOT_DIR).parts
    return (
        path.is_file()
        and path.suffix in AGENT_FILE_SUFFIXES
        and not any(part in AGENT_EXCLUDED_DIRS or part.startswith(".") for part in parts)
    )


RETRAIN_CHECK_SECONDS = 3600
RETRAIN_INTERVAL_SECONDS = 86400
_now = time.monotonic


async def _continuous_learning() -> None:
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


app = FastAPI(title="Nexus", version="2.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)


def basic_exempt_paths() -> tuple[str, ...]:
    return ("/healthz", "/api/ingest", "/api/agents/enroll", "/install-agent.sh", "/agent.tar.gz")


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

app.add_middleware(SecurityHeadersMiddleware)

app.include_router(agents_router)
app.include_router(panel_router)


def _pipeline() -> Pipeline:
    return app.state.pipeline


MAX_CLOCK_SKEW_SECONDS = 86400
MAX_JSON_FIELD_BYTES = 8192


def _sane_ts(ts: float | None, now: float) -> float:
    return now if ts is None or abs(ts - now) > MAX_CLOCK_SKEW_SECONDS else ts


def _canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _storable(value):
    return value.replace("\x00", "").encode("utf-8", "replace").decode() if isinstance(value, str) else value


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
        value = _storable(value)
        return value[:500] if isinstance(value, str) else value

    _storable_rule = field_validator("rule", mode="before")(_storable)


class BlockIn(BaseModel):
    ip: str
    rule: str = Field(max_length=64)
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list, max_length=16)
    until: float
    simulated: bool = False
    kind: Literal["block_port", "block_all", "rate_limit"] = "block_all"

    _valid_ip = field_validator("ip")(_canonical_ip)
    _storable_rule = field_validator("rule", mode="before")(_storable)


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
    with SessionLocal() as db:
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


@app.get("/install-agent.sh")
def install_agent_script():
    script = (ROOT_DIR / "install-agent.sh").read_text().replace("__NEXUS_PUBLIC_URL__", settings.public_url, 1)
    return Response(script, media_type="text/x-shellscript", headers={"Cache-Control": "no-store"})


@lru_cache(maxsize=1)
def _agent_tarball() -> bytes:
    package = sorted(p for p in (ROOT_DIR / "nexus_agent").rglob("*") if _ships_with_agent(p))
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed, tarfile.open(
        fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
    ) as tar:
        for path in [ROOT_DIR / "requirements-agent.txt", *package]:
            data = path.read_bytes()
            info = tarfile.TarInfo(path.relative_to(ROOT_DIR).as_posix())
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@app.get("/agent.tar.gz")
def agent_tarball():
    data = _agent_tarball()
    return Response(data, media_type="application/gzip", headers={"X-Nexus-Agent-SHA256": hashlib.sha256(data).hexdigest()})


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


@app.post("/api/retrain")
async def trigger_retrain():
    try:
        data = await asyncio.to_thread(load_db)
        if not data:
            raise HTTPException(400, "Not enough data to retrain.")
        bundle = await asyncio.to_thread(train, data, 12, 40, 500, 42, "online_manual")
        _pipeline().ensemble.install_bundle(bundle)
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
    for event in filter(_slack_worthy, events):
        await pipeline.notifier.notify_event(event)
    return {"status": "ok", "commands": commands, "acked": bool(payload.acked_commands)}


@app.get("/metrics")
async def prometheus_metrics():
    return Response(prom.render(_pipeline()), media_type=prom.CONTENT_TYPE)


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
