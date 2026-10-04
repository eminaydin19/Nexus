import asyncio
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("torch")

from backend.db import Anomaly, DefenseEvent, SessionLocal, init_db
from backend.defense import ActiveDefender
from backend.models.ensemble import Prediction
from backend.pipeline import Pipeline
from backend.schema import NodeSnapshot


class StubEnsemble:
    ready = True
    window = 4

    def __init__(self, score):
        self.score = score

    def reload_if_changed(self, _path):
        return False

    def info(self):
        return {"ready": True}

    def predict(self, _node, _vector):
        return Prediction(
            scores={"iforest": self.score, "lstm": None, "vae": self.score},
            ensemble=self.score,
            is_anomaly=True,
            severity="critical" if self.score >= 0.85 else "warning",
            culprit="network",
            flags=["iforest"],
            contributions={"cpu": 0.1, "memory": 0.1, "network": 0.7, "latency": 0.1},
        )


class StubNotifier:
    enabled = False

    async def notify(self, _anomaly):
        return False


def _run(score, ip):
    init_db()
    events = []

    async def sink(event):
        events.append(event)

    defender = ActiveDefender(critical_score=0.85, mode="dry_run", on_event=sink)
    pipeline = Pipeline(SimpleNamespace(name="webhook", interval=5), StubEnsemble(score), StubNotifier(), defender=defender)
    snap = NodeSnapshot("pipe-node", time.time(), 90.0, 50.0, 9000.0, 20.0)

    async def go():
        await pipeline.handle([snap], source_ip=ip)
        await asyncio.gather(*pipeline._tasks)

    asyncio.run(go())
    return pipeline, defender, events


def test_critical_anomaly_triggers_defense_with_source_ip():
    pipeline, defender, events = _run(0.95, "203.0.113.50")
    assert defender.safe_mode
    assert "203.0.113.50" in defender.blocked
    assert pipeline.node_ips["pipe-node"] == "203.0.113.50"
    assert {e["type"] for e in events} >= {"safe_mode", "block"}


def test_warning_anomaly_does_not_trigger_defense():
    _, defender, events = _run(0.6, "203.0.113.51")
    assert not defender.safe_mode and not defender.blocked and not events


def test_contributions_are_stored_and_served():
    _run(0.9, "203.0.113.52")
    with SessionLocal() as db:
        row = db.query(Anomaly).filter(Anomaly.node_id == "pipe-node").order_by(Anomaly.id.desc()).first()
    assert row.as_dict()["contributions"]["network"] == 0.7


def test_defense_events_can_be_persisted():
    from backend.main import _store_defense_event, recent_defense_events

    init_db()
    _store_defense_event({"ts": time.time(), "type": "block", "mode": "dry_run", "node": "n", "ip": "203.0.113.1",
                          "ok": True, "score": 0.9, "detail": "x" * 1000})
    latest = recent_defense_events(1)[0]
    assert latest["type"] == "block" and len(latest["detail"]) == 400
    with SessionLocal() as db:
        assert db.query(DefenseEvent).count() >= 1
