import base64
import time

import pytest

pytest.importorskip("torch")

from fastapi.testclient import TestClient
from sqlalchemy import text

BASIC = {"Authorization": "Basic " + base64.b64encode(b"admin:test-password").decode()}
METRICS = {"cpu_pct": 1.0, "memory_pct": 2.0, "net_kbps": 3.0, "latency_ms": 4.0}


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers=BASIC) as c:
        yield c


def new_token(client, name="srv"):
    r = client.post("/api/agents/tokens", json={"name": name})
    assert r.status_code == 200
    return r.json()["token"]


def enroll(client, hostname="host-a", token=None):
    return client.post("/api/agents/enroll", json={"token": token or new_token(client), "hostname": hostname})


def ingest(client, node_id, key):
    return client.post("/api/ingest", json=METRICS, headers={"X-API-Key": key})


def test_enroll_returns_node_and_working_key(client):
    body = enroll(client, "web.example.com").json()
    assert body["node_id"].startswith("web.example.com")
    assert ingest(client, body["node_id"], body["api_key"]).status_code == 200


def test_token_is_single_use(client):
    token = new_token(client)
    assert enroll(client, token=token).status_code == 200
    assert enroll(client, token=token).status_code == 401


def test_expired_token_rejected(client):
    from backend.db import EnrollToken, SessionLocal

    token = new_token(client)
    with SessionLocal() as db:
        db.query(EnrollToken).update({EnrollToken.expires_at: time.time() - 1})
        db.commit()
    assert enroll(client, token=token).status_code == 401


def test_enroll_failures_share_one_body(client):
    used = new_token(client)
    enroll(client, token=used)
    unknown = enroll(client, token="nope")
    again = enroll(client, token=used)
    assert unknown.status_code == again.status_code == 401
    assert unknown.json() == again.json()


def test_ingest_requires_valid_key(client):
    p = METRICS
    assert client.post("/api/ingest", json=p).status_code == 401
    assert client.post("/api/ingest", json=p, headers={"X-API-Key": "wrong"}).status_code == 401


def test_revoked_agent_rejected(client):
    a = enroll(client, "host-r").json()
    assert client.delete(f"/api/agents/{a['node_id']}").status_code == 200
    assert ingest(client, a["node_id"], a["api_key"]).status_code == 401
    assert client.delete("/api/agents/missing-node").status_code == 404


def test_duplicate_hostname_gets_distinct_node(client):
    first = enroll(client, "dup").json()
    second = enroll(client, "dup").json()
    assert first["node_id"] != second["node_id"]
    assert ingest(client, first["node_id"], first["api_key"]).status_code == 200


def test_hostname_is_sanitized(client):
    body = enroll(client, "bad host; drop").json()
    assert " " not in body["node_id"] and ";" not in body["node_id"]
    assert ingest(client, body["node_id"], body["api_key"]).status_code == 200


def test_ingest_sets_first_and_last_seen(client):
    from backend.db import Agent, SessionLocal

    a = enroll(client, "seen").json()
    ingest(client, a["node_id"], a["api_key"])
    with SessionLocal() as db:
        row = db.get(Agent, a["node_id"])
        assert row.first_seen is not None and row.last_seen >= row.first_seen
        assert row.mode == "observe" and row.max_mode == "observe"


def test_key_never_stored_plain(client):
    token = new_token(client)
    a = enroll(client, "plain", token=token).json()
    from backend.db import SessionLocal

    with SessionLocal() as db:
        dump = str([tuple(r) for t in ("agents", "enroll_tokens") for r in db.execute(text(f"SELECT * FROM {t}"))])
    assert a["api_key"] not in dump and token not in dump


def test_admin_routes_need_basic_auth_and_list_hides_hash(client):
    anon = TestClient(client.app)
    assert anon.post("/api/agents/tokens", json={"name": "x"}).status_code == 401
    assert anon.get("/api/agents").status_code == 401
    assert anon.delete("/api/agents/x").status_code == 401
    listing = client.get("/api/agents").json()["agents"]
    assert listing and all("key_hash" not in a for a in listing)
