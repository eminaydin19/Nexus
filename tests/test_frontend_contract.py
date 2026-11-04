import asyncio
import base64
import re
import time
from pathlib import Path
from pathlib import Path

import pytest

pytest.importorskip("torch")

from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.exc import OperationalError

from backend.db import ActiveBlock, Agent, SecurityEvent, SessionLocal, engine

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
BASIC = {"Authorization": "Basic " + base64.b64encode(b"admin:test-password").decode()}
METRICS = {"cpu_pct": 1.0, "memory_pct": 2.0, "net_kbps": 3.0, "latency_ms": 4.0}
SSH = {"rule": "ssh_bruteforce", "ip": "203.0.113.9", "action": "block_port", "ports": [22], "ttl": 3600, "evidence": "e"}
DAY = 86400


def sources() -> dict[str, str]:
    files = [p for p in FRONTEND.rglob("*") if p.suffix in {".html", ".css", ".js"} and "vendor" not in p.parts]
    return {p.relative_to(FRONTEND).as_posix(): p.read_text() for p in files}


@pytest.fixture(scope="module")
def html():
    return (FRONTEND / "index.html").read_text()


@pytest.fixture(scope="module")
def css():
    return (FRONTEND / "style.css").read_text()


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers=BASIC) as c:
        yield c


_n = iter(range(10_000))


def make_node(client, name=None):
    name = name or f"fc-{next(_n)}"
    token = client.post("/api/agents/tokens", json={"name": name}).json()["token"]
    body = client.post("/api/agents/enroll", json={"token": token, "hostname": name}).json()
    return body["node_id"], {"X-API-Key": body["api_key"]}


def ingest(client, key, **extra):
    r = client.post("/api/ingest", json={**METRICS, **extra}, headers=key)
    assert r.status_code == 200
    return r.json()


def edit_agent(node, **fields):
    with SessionLocal() as db:
        agent = db.get(Agent, node)
        for name, value in fields.items():
            setattr(agent, name, value)
        db.commit()


def overview(client):
    return client.get("/api/overview").json()


def attention(client, node):
    return {a["type"]: a for a in overview(client)["attention"] if a["node_id"] == node}


def server(client, node):
    return next(a for a in client.get("/api/agents").json()["agents"] if a["node_id"] == node)


# Static contract


def test_no_dark_theme_left(html, css):
    assert "prefers-color-scheme: dark" not in css and "themeToggle" not in html


def test_no_external_urls():
    for name, text in sources().items():
        assert not re.search(r"https?://", text), name


@pytest.mark.parametrize(
    "token",
    [
        "--bg: #F4F4F1", "--surface: #FFFFFF", "--fg: #141518", "--muted: #55575D", "--line: #D6D6D0",
        "--btn-bg: #141518", "--btn-fg: #FFFFFF", "--ok: #257D4B", "--ok-tint: #DDF0E4", "--danger: #B3261E",
        "--danger-tint: #FBE3E1", "--warn: #8A5A00", "--warn-tint: #FBF0D9", "--r: 12px", "color-scheme: light",
    ],
)
def test_tokens_exact(css, token):
    assert token in css


def test_no_safe_mode_references():
    for name, text in sources().items():
        assert not re.search(r"\bsafe.?mode\b", text, re.I), name


def test_font_is_self_hosted(css, html):
    assert (FRONTEND / "fonts" / "archivo.woff2").stat().st_size > 1000
    assert "url(fonts/archivo.woff2)" in css or 'url("fonts/archivo.woff2")' in css
    assert "fonts.googleapis" not in html + css


def test_no_html_injection_sinks():
    for name, text in sources().items():
        assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function", text), name


def test_no_inline_scripts_or_styles(html):
    assert "<style" not in html and not re.search(r"\sstyle=", html) and not re.search(r"\son[a-z]+=", html)
    assert all(re.search(r'\ssrc="', tag) for tag in re.findall(r"<script[^>]*>", html))
    for name, text in sources().items():
        if name.endswith(".js"):
            assert not re.search(r"""setAttribute\(\s*["']style|cssText|\.style\b""", text), name


def test_preview_note_is_gone():
    assert not any("Design preview" in text for text in sources().values())


def test_logo_is_one_colour():
    logo = (FRONTEND / "logo.svg").read_text()
    assert set(re.findall(r"#[0-9A-Fa-f]{3,8}\b", logo)) == {"#141518"}
    assert "Gradient" not in logo


def test_frontend_only_calls_existing_routes():
    from backend.main import app

    patterns = [re.sub(r"\{[^}]+\}", "[^/]+", path) for path in app.openapi()["paths"]]
    called = set()
    for name, text in sources().items():
        if name.endswith(".js"):
            for path in re.findall(r"""[`"'](/api/[^`"'?]*)""", text):
                called.add(re.sub(r"\$\{[^}]*\}", "x", path))
    assert "/api/overview" in called and "/api/customers" in called
    for path in called:
        assert any(re.fullmatch(p, path) for p in patterns), path


def test_old_panel_routes_are_gone():
    from backend.main import app

    paths = {r.path for r in app.routes if hasattr(r, "path")} | set(app.openapi()["paths"])
    assert "/api/overview" in paths and "/ws" not in paths and "/api/weights" not in paths
    assert not any(re.search(r"WebSocket|/api/defense|/api/weights", t) for t in sources().values())


def test_rule_names_live_in_one_module():
    from nexus_agent.rules import _RULES

    wording = (FRONTEND / "js" / "wording.js").read_text()
    for rule in [*_RULES, "distributed_flood", "breaker"]:
        assert re.search(rf"""\b{rule}\b["']?\s*[:,]""", wording), rule
    for name, text in sources().items():
        if name != "js/wording.js":
            assert "ssh_bruteforce" not in text, name


def test_offline_threshold_outlasts_the_agents_backoff():
    from backend.agents import OFFLINE_AFTER_SECONDS
    from nexus_agent.main import MAX_BACKOFF

    assert OFFLINE_AFTER_SECONDS == 90 and OFFLINE_AFTER_SECONDS > MAX_BACKOFF + 20


def test_a_server_in_backoff_is_not_offline(client):
    node, key = make_node(client)
    ingest(client, key)
    edit_agent(node, last_seen=time.time() - 75)
    assert server(client, node)["status"] == "online"
    edit_agent(node, last_seen=time.time() - 95)
    assert server(client, node)["status"] == "offline"


# Headers


@pytest.mark.parametrize("path", ["/", "/style.css", "/app.js", "/api/overview"])
def test_csp_on_dashboard_responses(client, path):
    csp = client.get(path).headers["content-security-policy"]
    for directive in (
        "default-src 'self'", "script-src 'self'", "style-src 'self'", "font-src 'self'", "img-src 'self' data:",
        "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'",
    ):
        assert directive in csp
    assert "unsafe" not in csp


def test_csp_on_auth_challenge(client):
    assert "content-security-policy" in TestClient(client.app).get("/").headers


# Auth


@pytest.mark.parametrize(
    "method,path", [("GET", "/api/overview"), ("GET", "/api/watch"), ("GET", "/api/watch/x"), ("POST", "/api/customers")]
)
def test_new_routes_require_auth(client, method, path):
    assert TestClient(client.app).request(method, path).status_code == 401


def test_customer_route_rejects_cross_origin(client):
    r = client.post("/api/customers", json={"ip": "203.0.113.1"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


# Overview


def test_overview_shape(client):
    assert {"protection", "blocked_24h", "rate_limited_24h", "attention", "recent", "active", "servers", "server_time"} <= set(
        overview(client)
    )


def test_blocked_24h_counts_only_real_successful_blocks(client):
    node, key = make_node(client)
    before = overview(client)
    ingest(
        client,
        key,
        events=[
            SSH,
            {**SSH, "action": "block_all", "ports": []},
            {**SSH, "simulated": True},
            {**SSH, "ok": False},
            {**SSH, "action": "alert"},
            {**SSH, "action": "rate_limit", "ports": []},
            {**SSH, "action": "rate_limit", "ports": [], "simulated": True},
        ],
    )
    after = overview(client)
    assert after["blocked_24h"] - before["blocked_24h"] == 2
    assert after["rate_limited_24h"] - before["rate_limited_24h"] == 1


def test_blocked_24h_ignores_older_events(client):
    node, _ = make_node(client)
    before = overview(client)["blocked_24h"]
    with SessionLocal() as db:
        db.add(SecurityEvent(node_id=node, ts=time.time() - DAY - 60, rule="r", ip="203.0.113.1", action="block_port"))
        db.commit()
    assert overview(client)["blocked_24h"] == before


def test_protection_counts_what_agents_report_not_what_was_requested(client):
    before = overview(client)["protection"]
    node, key = make_node(client)
    ingest(client, key, config={"max_mode": "enforce", "mode": "observe"})
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "enforce"}).status_code == 200
    now = overview(client)["protection"]
    assert now["blocking"] == before["blocking"] and now["watching"] == before["watching"] + 1
    assert server(client, node)["reported_mode"] == "observe"
    assert [p["type"] for p in server(client, node)["pending"]] == ["mode"]
    ingest(client, key, config={"max_mode": "enforce", "mode": "enforce"})
    assert overview(client)["protection"]["blocking"] == before["blocking"] + 1


def test_offline_servers_do_not_count_as_blocking(client):
    before = overview(client)["protection"]
    node, key = make_node(client)
    ingest(client, key, config={"max_mode": "enforce", "mode": "enforce"})
    edit_agent(node, last_seen=time.time() - 3600)
    now = overview(client)["protection"]
    assert now["blocking"] == before["blocking"] and now["offline"] == before["offline"] + 1
    assert now["total"] == before["total"] + 1
    assert server(client, node)["status"] == "offline"


def test_revoked_agents_leave_the_totals_and_their_blocks(client):
    before = overview(client)
    node, key = make_node(client)
    ingest(client, key, active_blocks=[{"ip": "203.0.113.8", "rule": "port_scan", "until": time.time() + 900}])
    assert overview(client)["active"]["blocked"] == before["active"]["blocked"] + 1
    client.delete(f"/api/agents/{node}")
    after = overview(client)
    assert after["protection"]["total"] == before["protection"]["total"]
    assert after["active"]["blocked"] == before["active"]["blocked"]
    assert all(s["node_id"] != node for s in after["servers"])
    assert server(client, node)["status"] == "revoked"


def test_active_counts_separate_blocks_limits_and_simulated(client):
    before = overview(client)["active"]
    _, key = make_node(client)
    until = time.time() + 900
    ingest(
        client,
        key,
        active_blocks=[
            {"ip": "203.0.113.1", "rule": "ssh_bruteforce", "ports": [22], "until": until, "kind": "block_port"},
            {"ip": "203.0.113.2", "rule": "conn_flood", "until": until, "kind": "rate_limit"},
            {"ip": "203.0.113.3", "rule": "web_probe", "until": until, "kind": "block_port", "simulated": True},
            {"ip": "203.0.113.4", "rule": "web_probe", "until": time.time() - 5, "kind": "block_port"},
        ],
    )
    after = overview(client)["active"]
    assert after["blocked"] - before["blocked"] == 1
    assert after["slowed"] - before["slowed"] == 1
    assert after["simulated"] - before["simulated"] == 1


def test_recent_merges_events_and_anomalies(client):
    from backend.db import Anomaly

    node, key = make_node(client)
    with SessionLocal() as db:
        db.add(
            Anomaly(
                node_id=node, ts=time.time() + 1, culprit="network", severity="warning", cpu_pct=1, memory_pct=1,
                net_kbps=1, latency_ms=1, ensemble_score=0.9, flags=[],
            )
        )
        db.commit()
    ingest(client, key, events=[SSH])
    recent = overview(client)["recent"]
    assert any(r.get("culprit") == "network" and r["node"] == node for r in recent)
    assert any(r.get("rule") == "ssh_bruteforce" and r.get("node_id") == node for r in recent)
    assert [r["ts"] for r in recent] == sorted((r["ts"] for r in recent), reverse=True)


# Attention


def test_attention_offline_includes_never_seen(client):
    node, _ = make_node(client)
    assert "offline" in attention(client, node)
    assert server(client, node)["status"] == "never"


def test_attention_offline_hides_stale_flags(client):
    node, key = make_node(client)
    ingest(client, key, config={"lift_pending": True, "breaker_open": True})
    edit_agent(node, last_seen=time.time() - 3600)
    assert set(attention(client, node)) == {"offline"}


def test_attention_online_server_is_quiet(client):
    node, key = make_node(client)
    ingest(client, key, config={"mode": "observe", "max_mode": "enforce"})
    assert attention(client, node) == {}


def test_attention_after_seven_days_of_watching_once(client):
    node, key = make_node(client)
    ingest(client, key, config={"mode": "observe", "max_mode": "enforce"})
    edit_agent(node, first_seen=time.time() - 8 * DAY)
    assert list(attention(client, node)) == ["watch_ready"]
    ingest(client, key, config={"mode": "enforce", "max_mode": "enforce"})
    assert attention(client, node) == {}
    assert server(client, node)["mode"] == "observe"  # nothing switched by itself


def test_attention_reports_agent_flags(client):
    node, key = make_node(client)
    ingest(
        client,
        key,
        config={
            "mode": "enforce", "enforce_rejected": True, "enforce_rejected_reason": "no_nft", "lift_pending": True,
            "breaker_open": True, "behind_cdn": True,
        },
    )
    found = attention(client, node)
    assert set(found) == {"enforce_rejected", "lift_pending", "breaker_open", "behind_cdn"}
    assert found["enforce_rejected"]["reason"] == "no_nft"


# Blocks


def test_blocks_carry_evidence_and_pending_removal(client):
    node, key = make_node(client)
    ingest(
        client,
        key,
        events=[{**SSH, "evidence": "old"}, {**SSH, "evidence": "new"}, {**SSH, "ip": "2001:db8:4f::9", "rule": "web_exploit", "evidence": "v6 line"}],
        active_blocks=[
            {"ip": "203.0.113.9", "rule": "ssh_bruteforce", "ports": [22], "until": time.time() + 900, "kind": "block_port"},
            {"ip": "2001:db8:4f::", "rule": "web_exploit", "ports": [80], "until": time.time() + 900, "kind": "block_port"},
            {"ip": "203.0.113.10", "rule": "port_scan", "until": time.time() + 900, "kind": "block_all"},
        ],
    )
    def rows():
        return {b["ip"]: b for b in client.get("/api/blocks").json()["blocks"] if b["node_id"] == node}

    assert rows()["203.0.113.9"]["evidence"] == "new"
    assert rows()["2001:db8:4f::"]["evidence"] == "v6 line"
    assert rows()["203.0.113.10"]["evidence"] == ""
    assert rows()["203.0.113.9"]["pending_removal"] is False
    client.post(f"/api/agents/{node}/unblock", json={"ip": "203.0.113.9"})
    assert rows()["203.0.113.9"]["pending_removal"] is True


def test_blocks_filter_simulated_and_expired(client):
    node, key = make_node(client)
    until = time.time() + 900
    ingest(
        client,
        key,
        active_blocks=[
            {"ip": "203.0.113.1", "rule": "r", "until": until},
            {"ip": "203.0.113.2", "rule": "r", "until": until, "simulated": True},
            {"ip": "203.0.113.3", "rule": "r", "until": time.time() - 1},
        ],
    )
    real = client.get("/api/blocks", params={"simulated": False}).json()["blocks"]
    assert [b["ip"] for b in real if b["node_id"] == node] == ["203.0.113.1"]


def test_blocks_survive_a_row_with_a_bad_address(client):
    node, _ = make_node(client)
    bad = "<img src=x onerror=__xss=1>"
    with SessionLocal() as db:
        db.add(ActiveBlock(node_id=node, ip=bad, rule="r", ports=[], until=time.time() + 900, kind="block_all"))
        db.add(SecurityEvent(node_id=node, ts=time.time(), rule="r", ip=bad, action="block_port", simulated=True))
        db.commit()
    assert client.get("/api/blocks").status_code == 200
    assert client.get(f"/api/watch/{node}").json()["items"][0]["ip"] == bad


def test_events_accept_several_actions(client):
    node, key = make_node(client)
    ingest(client, key, events=[SSH, {**SSH, "action": "block_all"}, {**SSH, "action": "alert"}])
    rows = client.get("/api/events", params={"node": node, "action": ["block_port", "block_all"]}).json()["events"]
    assert sorted(r["action"] for r in rows) == ["block_all", "block_port"]


# Watch


def watch_events(ip="198.51.100.61"):
    return [
        {"rule": "web_login_bruteforce", "ip": ip, "action": "block_port", "ports": [80, 443], "ttl": 900, "evidence": "a", "simulated": True},
        {"rule": "web_login_bruteforce", "ip": ip, "action": "block_port", "ports": [80, 443], "ttl": 900, "evidence": "b", "simulated": True},
        {"rule": "conn_flood", "ip": "198.51.100.62", "action": "rate_limit", "ttl": 600, "evidence": "c", "simulated": True},
        {"rule": "ssh_bruteforce", "ip": "203.0.113.70", "action": "block_port", "ports": [22], "ttl": 60, "evidence": "real"},
        {"rule": "distributed_flood", "ip": "0.0.0.0", "action": "alert", "evidence": "d", "simulated": True},
    ]


def test_watch_summary_uses_only_simulated_blocks(client):
    node, key = make_node(client)
    ingest(client, key, config={"mode": "observe"}, events=watch_events())
    body = client.get(f"/api/watch/{node}").json()
    assert body["window_days"] == 7 and body["node_id"] == node
    assert (body["would_block"], body["would_slow"]) == (2, 1)
    assert (body["addresses"], body["limited_addresses"]) == (1, 1)
    assert body["by_rule"][0] == {"rule": "web_login_bruteforce", "count": 2}
    item = next(i for i in body["items"] if i["rule"] == "web_login_bruteforce")
    assert item["count"] == 2 and item["evidence"] == "b" and item["ports"] == [80, 443] and item["ttl"] == 900
    assert not {i["ip"] for i in body["items"]} & {"0.0.0.0", "203.0.113.70"}


def test_watch_ignores_events_older_than_the_window(client):
    node, _ = make_node(client)
    with SessionLocal() as db:
        db.add(SecurityEvent(node_id=node, ts=time.time() - 8 * DAY, rule="r", ip="198.51.100.5", action="block_port", simulated=True))
        db.commit()
    assert client.get(f"/api/watch/{node}").json()["would_block"] == 0


def test_watch_unknown_server_is_404(client):
    assert client.get("/api/watch/nope").status_code == 404


def test_watch_ready_and_days(client):
    node, key = make_node(client)
    ingest(client, key)
    assert client.get(f"/api/watch/{node}").json()["ready"] is False
    edit_agent(node, first_seen=time.time() - 8 * DAY)
    body = client.get(f"/api/watch/{node}").json()
    assert body["ready"] is True and body["watched_days"] == 8


def test_watch_list_only_has_watching_servers(client):
    watching, key_a = make_node(client)
    blocking, key_b = make_node(client)
    ingest(client, key_a, config={"mode": "observe"}, events=watch_events())
    ingest(client, key_b, config={"mode": "enforce"}, events=watch_events())
    nodes = {s["node_id"]: s for s in client.get("/api/watch").json()["servers"]}
    assert watching in nodes and blocking not in nodes
    assert nodes[watching]["server"]["reported_mode"] == "observe"


def test_watch_list_skips_a_server_that_never_checked_in(client):
    node, _ = make_node(client)
    assert node not in {s["node_id"] for s in client.get("/api/watch").json()["servers"]}


def test_enforce_summary_leaves_out_allowlisted_and_server_wide(client):
    node, key = make_node(client)
    events = watch_events() + [
        {"rule": "port_scan", "ip": "0.0.0.0", "action": "block_all", "ttl": 60, "evidence": "x", "simulated": True},
        {"rule": "web_probe", "ip": "192.0.2.5", "action": "block_port", "ports": [80], "ttl": 60, "evidence": "x", "simulated": True},
    ]
    ingest(client, key, config={"mode": "observe"}, events=events)
    edit_agent(node, allowlist=["192.0.2.0/24"])
    body = client.get(f"/api/watch/{node}").json()
    assert (body["would_block"], body["addresses"], body["would_slow"], body["limited_addresses"]) == (2, 1, 1, 1)
    assert "web_probe" not in {r["rule"] for r in body["by_rule"]} and "port_scan" not in {r["rule"] for r in body["by_rule"]}
    # Server-wide rows stay visible on Watch, but nobody can review them as an address.
    assert {i["ip"] for i in body["items"]} == {"0.0.0.0", "198.51.100.61", "198.51.100.62"}
    assert body["waiting"] == 2


def test_watch_reports_true_count_past_the_cap(client):
    from backend.panel import MAX_WATCH_ITEMS

    node, _ = make_node(client)
    with SessionLocal() as db:
        for i in range(MAX_WATCH_ITEMS + 5):
            db.add(SecurityEvent(
                node_id=node, ts=time.time(), rule="r", ip=f"198.18.{i // 256}.{i % 256}", action="block_port", simulated=True,
                evidence=f"line {i}",
            ))
        db.commit()
    body = client.get(f"/api/watch/{node}").json()
    assert len(body["items"]) == MAX_WATCH_ITEMS and body["items_total"] == MAX_WATCH_ITEMS + 5
    assert body["waiting"] == MAX_WATCH_ITEMS + 5
    assert body["items"][0]["evidence"] == f"line {MAX_WATCH_ITEMS + 4}"


def test_watch_loads_the_listed_events_in_one_query(client):
    node, _ = make_node(client)
    with SessionLocal() as db:
        for i in range(30):
            db.add(SecurityEvent(node_id=node, ts=time.time(), rule="r", ip=f"198.18.0.{i}", action="block_port", simulated=True, evidence="e"))
        db.commit()
    statements = []
    listen = lambda conn, cursor, sql, *rest: statements.append(sql) if "security_events" in sql else None
    event.listen(engine, "before_cursor_execute", listen)
    try:
        assert len(client.get(f"/api/watch/{node}").json()["items"]) == 30
    finally:
        event.remove(engine, "before_cursor_execute", listen)
    assert len(statements) == 2


def test_ipv6_rows_carry_the_range_a_block_covers(client):
    node, key = make_node(client)
    v6 = {"rule": "web_exploit", "ip": "2001:db8:9::5", "action": "block_port", "ports": [80], "ttl": 60, "evidence": "x", "simulated": True}
    ingest(client, key, config={"mode": "observe"}, events=[v6, {**SSH, "simulated": True}],
           active_blocks=[{"ip": "2001:db8:9::", "rule": "web_exploit", "until": time.time() + 900}])
    covers = {i["ip"]: i["cover"] for i in client.get(f"/api/watch/{node}").json()["items"]}
    assert covers == {"2001:db8:9::5": "2001:db8:9::/64", "203.0.113.9": "203.0.113.9"}
    rows = client.get("/api/events", params={"node": node}).json()["events"]
    assert {r["cover"] for r in rows} == {"2001:db8:9::/64", "203.0.113.9"}
    block = next(b for b in client.get("/api/blocks").json()["blocks"] if b["node_id"] == node)
    assert block["cover"] == "2001:db8:9::/64"


# Mode commands


def test_a_newer_mode_replaces_the_pending_one(client):
    node, key = make_node(client)
    ingest(client, key, config={"max_mode": "enforce", "mode": "enforce"})
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "off"}).status_code == 200
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "observe"}).status_code == 200
    assert client.put(f"/api/agents/{node}/mode", json={"mode": "enforce"}).status_code == 200
    assert [p["payload"] for p in server(client, node)["pending"]] == [{"mode": "enforce"}]
    delivered = ingest(client, key)["commands"]
    assert [c["payload"] for c in delivered] == [{"mode": "enforce"}]


def test_a_new_mode_leaves_other_pending_commands(client):
    node, key = make_node(client)
    ingest(client, key, config={"max_mode": "enforce"})
    client.post(f"/api/agents/{node}/unblock", json={"ip": "203.0.113.5"})
    client.put(f"/api/agents/{node}/mode", json={"mode": "off"})
    client.put(f"/api/agents/{node}/mode", json={"mode": "observe"})
    assert types(client, key) == ["unblock", "mode"]


@pytest.mark.parametrize("path", ["install.sh", "install-agent.sh", "README.md"])
def test_printed_enroll_command_keeps_the_token_out_of_ps(path):
    text = (Path(__file__).resolve().parent.parent / path).read_text()
    assert "sudo --preserve-env=NEXUS_ENROLL_TOKEN bash" in text
    assert "sudo bash -s -- --token" not in text and "sudo bash -s -- --url" not in text


# Basic auth by scope type


async def run_auth(scope_type):
    from backend.security import BasicAuthMiddleware

    called, sent = [], []

    async def inner(scope, receive, send):
        called.append(scope["type"])

    async def send(message):
        sent.append(message)

    credentials = base64.b64encode(b"u:p")
    scope = {"type": scope_type, "path": "/x", "headers": [(b"authorization", b"Basic " + credentials)]}
    await BasicAuthMiddleware(inner, username="u", password="p", exempt_paths=frozenset())(scope, None, send)
    return called, sent


def test_auth_passes_lifespan_and_refuses_websockets_even_with_credentials():
    assert asyncio.run(run_auth("lifespan"))[0] == ["lifespan"]
    assert asyncio.run(run_auth("http"))[0] == ["http"]
    called, sent = asyncio.run(run_auth("websocket"))
    assert called == [] and sent == [{"type": "websocket.close", "code": 1008}]


# Customers


def types(client, key):
    return [c["type"] for c in ingest(client, key)["commands"]]


def test_customer_merges_allowlist_on_every_live_server(client):
    a, key_a = make_node(client)
    b, key_b = make_node(client)
    gone, key_gone = make_node(client)
    assert client.put(f"/api/agents/{a}/allowlist", json=["192.0.2.0/24"]).status_code == 200
    client.delete(f"/api/agents/{gone}")
    r = client.post("/api/customers", json={"ip": "203.0.113.50"})
    assert r.status_code == 200
    body = r.json()
    assert {a, b} <= set(body["sent"]) and gone not in body["sent"]
    assert server(client, a)["allowlist"] == ["192.0.2.0/24", "203.0.113.50/32"]
    assert server(client, b)["allowlist"] == ["203.0.113.50/32"]
    commands = ingest(client, key_a)["commands"]
    assert [c["type"] for c in commands] == ["allowlist", "allowlist", "unblock"]
    assert commands[1]["payload"] == {"ips": ["192.0.2.0/24", "203.0.113.50/32"]}
    assert commands[2]["payload"] == {"ip": "203.0.113.50"}
    assert server(client, gone)["allowlist"] == []


def test_customer_pending_until_ack(client):
    node, key = make_node(client)
    client.post("/api/customers", json={"ip": "203.0.113.51"})
    assert {p["type"] for p in server(client, node)["pending"]} >= {"allowlist", "unblock"}
    ids = [c["id"] for c in ingest(client, key)["commands"]]
    ingest(client, key, acked_commands=ids)
    assert server(client, node)["pending"] == []


def test_customer_is_idempotent(client):
    node, key = make_node(client)
    client.post("/api/customers", json={"ip": "203.0.113.52"})
    client.post("/api/customers", json={"ip": "203.0.113.52"})
    assert server(client, node)["allowlist"].count("203.0.113.52/32") == 1
    assert types(client, key).count("allowlist") == 1


def test_customer_ipv6_covers_the_block_range(client):
    node, _ = make_node(client)
    assert client.post("/api/customers", json={"ip": "2001:db8:4f::9"}).status_code == 200
    assert server(client, node)["allowlist"] == ["2001:db8:4f::/64"]


def test_customer_ipv4_mapped_becomes_ipv4(client):
    node, _ = make_node(client)
    assert client.post("/api/customers", json={"ip": "::ffff:203.0.113.53"}).status_code == 200
    assert server(client, node)["allowlist"] == ["203.0.113.53/32"]


@pytest.mark.parametrize("ip", ["0.0.0.0", "::", "0.0.0.0/0", "::/0", "nonsense", "<img src=x>", "203.0.113.0/33"])
def test_customer_rejects_what_is_not_one_address(client, ip):
    assert client.post("/api/customers", json={"ip": ip}).status_code == 400


def test_customer_reports_a_full_allowlist_instead_of_dropping_entries(client):
    from backend.agents import MAX_ALLOWLIST

    node, _ = make_node(client)
    full = [f"10.{i // 256}.{i % 256}.0/24" for i in range(MAX_ALLOWLIST)]
    edit_agent(node, allowlist=full)
    body = client.post("/api/customers", json={"ip": "203.0.113.54"}).json()
    assert node in body["full"] and node not in body["sent"]
    assert server(client, node)["allowlist"] == full
    edit_agent(node, allowlist=[])


def test_customer_accepts_a_range_through_the_same_validation(client):
    node, key = make_node(client)
    assert client.put(f"/api/agents/{node}/allowlist", json=["192.0.2.0/24"]).status_code == 200
    body = client.post("/api/customers", json={"ip": "198.51.100.9/24"}).json()
    assert body["entry"] == "198.51.100.0/24" and node in body["sent"]
    assert server(client, node)["allowlist"] == ["192.0.2.0/24", "198.51.100.0/24"]
    commands = ingest(client, key)["commands"]
    # A range has no single address to unblock; the agent lifts covered blocks when the allowlist arrives.
    assert [c["type"] for c in commands] == ["allowlist", "allowlist"]
    edit_agent(node, allowlist=[])


def test_customer_ipv6_range_is_never_narrower_than_a_block(client):
    node, _ = make_node(client)
    assert client.post("/api/customers", json={"ip": "2001:db8:5::1/120"}).json()["entry"] == "2001:db8:5::/64"
    assert server(client, node)["allowlist"] == ["2001:db8:5::/64"]


def test_customer_failure_on_one_server_is_reported_and_keeps_the_rest(client, monkeypatch):
    import backend.panel as panel

    bad, _ = make_node(client)
    good, _ = make_node(client)
    real = panel.enqueue

    def flaky(db, node, *args, **kwargs):
        if node == bad:
            raise OperationalError("insert", {}, Exception("disk full"))
        return real(db, node, *args, **kwargs)

    monkeypatch.setattr(panel, "enqueue", flaky)
    r = client.post("/api/customers", json={"ip": "203.0.113.60"})
    assert r.status_code == 200
    body = r.json()
    assert bad in body["failed"] and bad not in body["sent"] and good in body["sent"]
    monkeypatch.undo()
    # The allowlist write and its command stand or fall together.
    assert "203.0.113.60/32" not in server(client, bad)["allowlist"] and server(client, bad)["pending"] == []
    assert "203.0.113.60/32" in server(client, good)["allowlist"]
    assert {p["type"] for p in server(client, good)["pending"]} == {"allowlist", "unblock"}


def test_customer_removal_reaches_every_server_holding_the_entry(client):
    a, key_a = make_node(client)
    b, _ = make_node(client)
    client.put(f"/api/agents/{a}/allowlist", json=["192.0.2.0/24"])
    client.post("/api/customers", json={"ip": "203.0.113.61"})
    r = client.post("/api/customers/remove", json={"entry": "203.0.113.61/32"})
    assert r.status_code == 200
    assert {a, b} <= set(r.json()["sent"])
    assert server(client, a)["allowlist"] == ["192.0.2.0/24"] and server(client, b)["allowlist"] == []
    assert ingest(client, key_a)["commands"][-1]["payload"] == {"ips": ["192.0.2.0/24"]}
    assert client.post("/api/customers/remove", json={"entry": "nonsense"}).status_code == 400


def test_watch_item_stays_pending_until_ack_then_leaves(client):
    node, key = make_node(client)
    ingest(client, key, config={"mode": "observe"}, events=watch_events("198.51.100.77"))
    client.post("/api/customers", json={"ip": "198.51.100.77"})
    item = next(i for i in client.get(f"/api/watch/{node}").json()["items"] if i["ip"] == "198.51.100.77")
    assert item["pending"] is True
    ids = [c["id"] for c in ingest(client, key)["commands"]]
    ingest(client, key, acked_commands=ids)
    assert "198.51.100.77" not in {i["ip"] for i in client.get(f"/api/watch/{node}").json()["items"]}


# Add server


def test_token_response_says_where_agents_should_enroll(client, monkeypatch):
    from backend.agents import settings

    monkeypatch.setattr(settings, "public_url", "https://nexus.example")
    assert client.post("/api/agents/tokens", json={"name": "x"}).json()["public_url"] == "https://nexus.example"
    monkeypatch.setattr(settings, "public_url", "")
    assert client.post("/api/agents/tokens", json={"name": "x"}).json()["public_url"] == ""
