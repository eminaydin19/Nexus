import base64
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("torch")

from fastapi.testclient import TestClient

from backend.commands import ack, enqueue, pending
from backend.db import Anomaly, SessionLocal
from backend.models.ensemble import Prediction

BASIC = {"Authorization": "Basic " + base64.b64encode(b"admin:test-password").decode()}
METRICS = {"cpu_pct": 1.0, "memory_pct": 2.0, "net_kbps": 3.0, "latency_ms": 4.0}
EVENT = {"rule": "ssh_bruteforce", "ip": "203.0.113.9", "action": "block_port", "ports": [22], "ttl": 300}


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers=BASIC) as c:
        yield c


_n = iter(range(10_000))


def make_node(client):
    name = f"v2-{next(_n)}"
    token = client.post("/api/agents/tokens", json={"name": name}).json()["token"]
    body = client.post("/api/agents/enroll", json={"token": token, "hostname": name}).json()
    return body["node_id"], {"X-API-Key": body["api_key"]}


def ingest(client, key, **extra):
    return client.post("/api/ingest", json={**METRICS, **extra}, headers=key)


def test_only_three_command_types():
    with SessionLocal() as db:
        with pytest.raises(ValueError):
            enqueue(db, "n", "exec", {})


def test_commands_delivered_until_acked(client):
    node, key = make_node(client)
    assert client.post(f"/api/agents/{node}/unblock", json={"ip": "203.0.113.5"}).status_code == 200
    first = ingest(client, key).json()
    assert [c["type"] for c in first["commands"]] == ["unblock"]
    assert first["commands"][0]["payload"] == {"ip": "203.0.113.5"}
    again = ingest(client, key).json()
    assert again["commands"] == first["commands"]
    done = ingest(client, key, acked_commands=[first["commands"][0]["id"]]).json()
    assert done["commands"] == [] and done["acked"] is True


def test_ack_ignores_other_nodes_commands(client):
    a, key_a = make_node(client)
    b, key_b = make_node(client)
    client.post(f"/api/agents/{a}/unblock", json={"ip": "203.0.113.6"})
    cid = ingest(client, key_a).json()["commands"][0]["id"]
    ingest(client, key_b, acked_commands=[cid])
    assert [c["id"] for c in ingest(client, key_a).json()["commands"]] == [cid]
    with SessionLocal() as db:
        ack(db, a, [cid])
        assert pending(db, a) == []


def test_mode_above_max_rejected(client):
    node, key = make_node(client)
    ingest(client, key, config={"max_mode": "observe"})
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "enforce"}).status_code == 409
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "off"}).status_code == 200
    ingest(client, key, config={"max_mode": "enforce"})
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "enforce"}).status_code == 200
    types = [c["type"] for c in ingest(client, key).json()["commands"]]
    assert types == ["mode", "mode"]


def test_allowlist_validated_and_enqueued(client):
    node, key = make_node(client)
    assert client.put(f"/api/agents/{node}/allowlist", json=["10.0.0.0/8", "nope"]).status_code == 400
    assert client.put(f"/api/agents/{node}/allowlist", json=["10.0.0.0/8", "::1"]).status_code == 200
    cmd = ingest(client, key).json()["commands"][0]
    assert cmd["type"] == "allowlist" and cmd["payload"]["ips"] == ["10.0.0.0/8", "::1/128"]


def test_unknown_node_and_bad_ip(client):
    assert client.post("/api/agents/ghost/unblock", json={"ip": "1.2.3.4"}).status_code == 404
    assert client.put("/api/agents/ghost/allowlist", json=[]).status_code == 404
    assert client.put("/api/agents/ghost/mode", json={"mode": "off"}).status_code == 404
    node, _ = make_node(client)
    assert client.post(f"/api/agents/{node}/unblock", json={"ip": "x"}).status_code == 400


def test_events_stored_filtered_and_broadcast(client):
    node, key = make_node(client)
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        ingest(client, key, events=[EVENT, {**EVENT, "rule": "port_scan", "action": "alert", "simulated": True}])
        msgs = [ws.receive_json(), ws.receive_json()]
    ev = next(m for m in msgs if m["type"] == "events")
    assert ev["node"] == node and len(ev["events"]) == 2
    rows = client.get("/api/events", params={"node": node}).json()["events"]
    assert {r["rule"] for r in rows} == {"ssh_bruteforce", "port_scan"}
    sim = client.get("/api/events", params={"node": node, "simulated": True}).json()["events"]
    assert [r["rule"] for r in sim] == ["port_scan"]
    assert len(client.get("/api/events", params={"node": node, "action": "block_port"}).json()["events"]) == 1


def test_evidence_truncated_and_ip_validated(client):
    node, key = make_node(client)
    assert ingest(client, key, events=[{**EVENT, "ip": "999.1.1.1"}]).status_code == 422
    assert ingest(client, key, events=[{**EVENT, "evidence": "x" * 900}]).status_code == 200
    assert len(client.get("/api/events", params={"node": node}).json()["events"][0]["evidence"]) == 500


@pytest.mark.parametrize(
    "patch",
    [{"action": "format_disk"}, {"ports": [0]}, {"ports": [1] * 17}, {"ttl": 86401}, {"rule": "r" * 65}],
)
def test_event_field_limits(client, patch):
    _, key = make_node(client)
    assert ingest(client, key, events=[{**EVENT, **patch}]).status_code == 422


def test_event_count_limit(client):
    _, key = make_node(client)
    assert ingest(client, key, events=[EVENT] * 501).status_code == 422


def test_active_blocks_replace_previous_list(client):
    node, key = make_node(client)
    block = {"ip": "203.0.113.20", "rule": "port_scan", "ports": [22], "until": time.time() + 60, "simulated": False}
    ingest(client, key, active_blocks=[block, {**block, "ip": "203.0.113.21"}])
    ingest(client, key, active_blocks=[{**block, "ip": "203.0.113.22"}])
    blocks = [b for b in client.get("/api/blocks").json()["blocks"] if b["node_id"] == node]
    assert [b["ip"] for b in blocks] == ["203.0.113.22"]


def test_ingest_stores_agent_info(client):
    from backend.db import Agent

    node, key = make_node(client)
    ingest(client, key, version="1.2.3", capabilities={"nft": True}, config={"max_mode": "enforce"})
    with SessionLocal() as db:
        a = db.get(Agent, node)
        assert (a.version, a.capabilities, a.max_mode) == ("1.2.3", {"nft": True}, "enforce")


def test_node_comes_from_key_only(client):
    node, key = make_node(client)
    assert ingest(client, key, node_id="someone-else").status_code == 200
    assert any(n["node"] == node for n in client.get("/api/nodes").json()["nodes"])


class _Critical:
    ready = True
    window = 4

    def reload_if_changed(self, _path):
        return False

    def info(self):
        return {"ready": True}

    def predict(self, _node, _vector):
        return Prediction(
            scores={"iforest": 0.95, "lstm": None, "vae": 0.95, "transformer": None},
            ensemble=0.95,
            is_anomaly=True,
            severity="critical",
            culprit="network",
            flags=["iforest"],
            contributions={"cpu": 0.1, "memory": 0.1, "network": 0.7, "latency": 0.1},
        )


def test_ml_anomaly_never_creates_block(client, monkeypatch):
    node, key = make_node(client)
    monkeypatch.setattr(client.app.state.pipeline, "ensemble", _Critical())
    body = ingest(client, key).json()
    assert body["commands"] == []
    assert client.get("/api/events", params={"node": node}).json()["events"] == []
    assert not [b for b in client.get("/api/blocks").json()["blocks"] if b["node_id"] == node]
    with SessionLocal() as db:
        row = db.query(Anomaly).filter(Anomaly.node_id == node).first()
    assert row.as_dict()["contributions"]["network"] == 0.7


def test_timestamp_skew_uses_server_time(client):
    from backend.db import Metric

    node, key = make_node(client)
    ingest(client, key, timestamp=time.time() + 2 * 86400, events=[{**EVENT, "ts": time.time() - 3 * 86400}])
    with SessionLocal() as db:
        assert abs(db.query(Metric).filter(Metric.node_id == node).one().ts - time.time()) < 60
    ev = client.get("/api/events", params={"node": node}).json()["events"][0]
    assert abs(ev["ts"] - time.time()) < 60


def test_defense_routes_are_gone(client):
    assert client.get("/api/defense").status_code in (404, 405)
    assert client.post("/api/defense/unblock/1.2.3.4").status_code in (404, 405)


def test_critical_events_forwarded_to_slack(client, monkeypatch):
    node, key = make_node(client)
    sent = []

    async def fake(event):
        sent.append(event)
        return True

    monkeypatch.setattr(client.app.state.pipeline.notifier, "notify_event", fake)
    ingest(client, key, events=[
        {**EVENT, "simulated": True},
        {**EVENT, "action": "alert", "rule": "other"},
        {**EVENT, "action": "alert", "rule": "distributed_flood"},
        {**EVENT, "action": "rate_limit", "rule": "http_flood"},
    ])
    assert [e["rule"] for e in sent] == ["distributed_flood", "http_flood"]
    assert all(e["node_id"] == node for e in sent)


def _real_notifier(monkeypatch):
    import asyncio

    from backend.alerting import SlackNotifier

    texts = []

    async def post(self, text):
        texts.append(text)
        return True

    monkeypatch.setattr(SlackNotifier, "_post", post)
    return SlackNotifier("http://slack.invalid", 900), texts, asyncio.run


def _ev(rule, **kw):
    from backend.db import SecurityEvent

    base = SecurityEvent(node_id="n", ts=1.0, rule=rule, ip="203.0.113.9", action="block_port", ports=[22], ttl=300,
                         evidence="x", simulated=False, ok=True)
    return {**base.as_dict(), **kw}


def test_event_cooldown_is_per_node_and_rule(monkeypatch):
    n, texts, run = _real_notifier(monkeypatch)
    assert run(n.notify_event(_ev("ssh_bruteforce")))
    assert run(n.notify_event(_ev("distributed_flood", action="alert")))
    assert not run(n.notify_event(_ev("ssh_bruteforce")))
    anomaly = {"node": "n", "severity": "critical", "culprit": "cpu", "scores": {"ensemble": 0.9},
               "cpu_pct": 1, "memory_pct": 1, "net_kbps": 1, "latency_ms": 1}
    assert run(n.notify(anomaly))
    assert len(texts) == 3


def test_event_slack_text_has_no_score_and_escapes_evidence(monkeypatch):
    n, texts, run = _real_notifier(monkeypatch)
    run(n.notify_event(_ev("r", evidence="<!channel> a&b")))
    assert "Score" not in texts[0]
    assert "&lt;!channel&gt; a&amp;b" in texts[0] and "<!channel>" not in texts[0]


def test_invalid_max_mode_ignored(client):
    node, key = make_node(client)
    ingest(client, key, config={"max_mode": "enforce"})
    for bad in ("root", ["enforce"], 5, None):
        assert ingest(client, key, config={"max_mode": bad}).status_code == 200
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "enforce"}).status_code == 200


def test_event_slack_text_escapes_every_field(monkeypatch):
    n, texts, run = _real_notifier(monkeypatch)
    run(n.notify_event(_ev("<!channel>", node_id="<!here>", action="<a>", ip="<i>", ports=["<p>"])))
    assert "<" not in texts[0].replace(":rotating_light:", "") and "&lt;!channel&gt;" in texts[0]
