import asyncio
import json
import logging
import time
from datetime import timedelta

import numpy as np

from backend.alerting import SlackNotifier
from backend.config import settings
from backend.db import Anomaly, Metric, SessionLocal
from backend.ingestion.base import Source
from backend.models.ensemble import Ensemble
from backend.schema import NodeSnapshot

log = logging.getLogger(__name__)

STORE_SPACING_SECONDS = 30.0
PRUNE_INTERVAL_SECONDS = 3600.0
SEND_TIMEOUT_SECONDS = 5.0


def recent_anomalies(limit: int, node: str | None = None) -> list[dict]:
    with SessionLocal() as db:
        query = db.query(Anomaly)
        if node:
            query = query.filter(Anomaly.node_id == node)
        return [a.as_dict() for a in query.order_by(Anomaly.ts.desc(), Anomaly.id.desc()).limit(limit)]


def metric_history(node: str, minutes: int, points: int) -> list[dict]:
    since = time.time() - minutes * 60
    with SessionLocal() as db:
        rows = db.query(Metric).filter(Metric.node_id == node, Metric.ts >= since).order_by(Metric.ts).all()
    stride = max(1, -(-len(rows) // points))
    return [
        {
            "ts": m.ts,
            "cpu_pct": m.cpu_pct,
            "memory_pct": m.memory_pct,
            "net_kbps": m.net_kbps,
            "latency_ms": m.latency_ms,
            "score": m.score,
            "is_anomaly": m.is_anomaly,
        }
        for i, m in enumerate(rows)
        if i % stride == 0 or m.is_anomaly
    ]


class Pipeline:
    def __init__(self, source: Source, ensemble: Ensemble, notifier: SlackNotifier):
        self.source = source
        self.ensemble = ensemble
        self.notifier = notifier
        self.latest: dict[str, dict] = {}
        self.clients: set = set()
        self.last_poll: float | None = None
        self.last_error: str | None = None
        self._last_stored: dict[str, float] = {}
        self._last_prune = 0.0
        self._retention_days = 1 if source.name == "mock" else settings.retention_days

    def health(self) -> dict:
        return {
            "status": "ok",
            "source": self.source.name,
            "interval": self.source.interval,
            "nodes": len(self.latest),
            "clients": len(self.clients),
            "last_poll": self.last_poll,
            "last_error": self.last_error,
            "server_time": time.time(),
            "model": self.ensemble.info(),
            "slack": self.notifier.enabled,
        }

    def prime_from_db(self) -> None:
        if not self.ensemble.ready:
            return
        since = time.time() - 86400
        with SessionLocal() as db:
            nodes = [r[0] for r in db.query(Metric.node_id).filter(Metric.ts >= since).distinct()]
            for node in nodes:
                rows = (
                    db.query(Metric)
                    .filter(Metric.node_id == node)
                    .order_by(Metric.ts.desc())
                    .limit(self.ensemble.window)
                    .all()
                )
                raw = np.array([[m.cpu_pct, m.memory_pct, m.net_kbps, m.latency_ms] for m in reversed(rows)])
                self.ensemble.prime(node, raw)
        log.info("primed %d node buffers from history", len(nodes))

    async def run(self) -> None:
        while True:
            try:
                snapshots = await self.source.poll()
                self.last_poll = time.time()
                self.last_error = None
                if snapshots:
                    await self.handle(snapshots)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception("poll cycle failed")
                self.last_error = f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(self.source.interval)

    async def handle(self, snapshots: list[NodeSnapshot]) -> None:
        payloads, anomalies = await asyncio.to_thread(self._score_and_store, snapshots)
        for payload in payloads:
            self.latest[payload["node"]] = payload
        await self.broadcast({"type": "update", "nodes": payloads, "anomalies": anomalies})
        for anomaly in anomalies:
            if anomaly["severity"] == "critical":
                await self.notifier.notify(anomaly)

    def _score_and_store(self, snapshots: list[NodeSnapshot]) -> tuple[list[dict], list[dict]]:
        if self.ensemble.reload_if_changed(settings.bundle_path):
            self.prime_from_db()

        payloads: list[dict] = []
        anomalies: list[dict] = []
        with SessionLocal() as db:
            for snap in snapshots:
                prediction = self.ensemble.predict(snap.node_id, snap.vector())
                is_anomaly = bool(prediction and prediction.is_anomaly)
                scores = None
                if prediction:
                    scores = {**prediction.scores, "ensemble": prediction.ensemble}

                payloads.append(
                    {
                        "node": snap.node_id,
                        "ts": snap.timestamp,
                        "cpu_pct": snap.cpu_pct,
                        "memory_pct": snap.memory_pct,
                        "net_kbps": snap.net_kbps,
                        "latency_ms": snap.latency_ms,
                        "status": "learning" if prediction is None else "anomaly" if is_anomaly else "ok",
                        "scores": scores,
                        "severity": prediction.severity if prediction else None,
                        "culprit": prediction.culprit if prediction else None,
                        "flags": prediction.flags if prediction else [],
                    }
                )
                db.add(
                    Metric(
                        node_id=snap.node_id,
                        ts=snap.timestamp,
                        cpu_pct=snap.cpu_pct,
                        memory_pct=snap.memory_pct,
                        net_kbps=snap.net_kbps,
                        latency_ms=snap.latency_ms,
                        score=prediction.ensemble if prediction else None,
                        is_anomaly=is_anomaly,
                    )
                )

                if is_anomaly and snap.timestamp - self._last_stored.get(snap.node_id, float("-inf")) >= STORE_SPACING_SECONDS:
                    self._last_stored[snap.node_id] = snap.timestamp
                    row = Anomaly(
                        node_id=snap.node_id,
                        ts=snap.timestamp,
                        culprit=prediction.culprit,
                        severity=prediction.severity,
                        cpu_pct=snap.cpu_pct,
                        memory_pct=snap.memory_pct,
                        net_kbps=snap.net_kbps,
                        latency_ms=snap.latency_ms,
                        ensemble_score=prediction.ensemble,
                        if_score=prediction.scores["iforest"],
                        lstm_score=prediction.scores["lstm"],
                        vae_score=prediction.scores["vae"],
                        flags=prediction.flags,
                    )
                    db.add(row)
                    db.flush()
                    anomalies.append(row.as_dict())
            db.commit()
            self._prune(db)
        return payloads, anomalies

    def _prune(self, db) -> None:
        now = time.time()
        if now - self._last_prune < PRUNE_INTERVAL_SECONDS:
            return
        self._last_prune = now
        cutoff = now - timedelta(days=self._retention_days).total_seconds()
        db.query(Metric).filter(Metric.ts < cutoff).delete(synchronize_session=False)
        db.query(Anomaly).filter(Anomaly.ts < cutoff).delete(synchronize_session=False)
        db.commit()

    async def broadcast(self, message: dict) -> None:
        if not self.clients:
            return
        text = json.dumps(message)
        dead = []
        for ws in list(self.clients):
            try:
                await asyncio.wait_for(ws.send_text(text), SEND_TIMEOUT_SECONDS)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)
