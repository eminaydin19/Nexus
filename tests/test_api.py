import pytest

pytest.importorskip("torch")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from backend import db

GOOD = {"node_id": "web-1", "cpu_pct": 12.5, "memory_pct": 40.0, "net_kbps": 120.0, "latency_ms": 18.0}
KEY = {"X-API-Key": "test-key"}


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app) as c:
        yield c


def test_healthz_is_open(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_ingest_requires_api_key(client):
    assert client.post("/api/ingest", json=GOOD).status_code == 401
    assert client.post("/api/ingest", json=GOOD, headers={"X-API-Key": "nope"}).status_code == 401


def test_ingest_accepts_valid_payload_and_exposes_node(client):
    assert client.post("/api/ingest", json=GOOD, headers=KEY).status_code == 200
    nodes = client.get("/api/nodes").json()["nodes"]
    assert any(n["node"] == "web-1" for n in nodes)


@pytest.mark.parametrize(
    "patch",
    [
        {"cpu_pct": 140},
        {"memory_pct": -1},
        {"net_kbps": -5},
        {"node_id": ""},
        {"node_id": "bad node; drop table"},
        {"node_id": "x" * 200},
    ],
)
def test_ingest_rejects_bad_payloads(client, patch):
    assert client.post("/api/ingest", json={**GOOD, **patch}, headers=KEY).status_code == 422


def test_defense_endpoint_reports_mode_and_events(client):
    body = client.get("/api/defense").json()
    assert body["mode"] == "dry_run"
    assert body["blocked"] == [] and isinstance(body["events"], list)


def test_unblock_validates_input(client):
    assert client.post("/api/defense/unblock/not-an-ip").status_code == 400
    assert client.post("/api/defense/unblock/203.0.113.77").status_code == 404


def test_prometheus_metrics(client):
    client.post("/api/ingest", json=GOOD, headers=KEY)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    text_body = response.text
    for name in ("nexus_nodes", "nexus_safe_mode", "nexus_ingest_total", 'nexus_node_cpu_pct{node="web-1"}'):
        assert name in text_body


def test_migration_adds_contributions_column(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE anomalies (id INTEGER PRIMARY KEY, node_id TEXT)"))
    monkeypatch.setattr(db, "engine", engine)
    db._migrate()
    db._migrate()  # idempotent
    assert "contributions" in {c["name"] for c in inspect(engine).get_columns("anomalies")}
