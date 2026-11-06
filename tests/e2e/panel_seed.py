import os
import random
import sys
import time

import requests

from backend.db import ActiveBlock, Agent, Anomaly, Metric, SecurityEvent, SessionLocal

BASE = "http://127.0.0.1:8000"
AUTH = (os.environ["DASHBOARD_USER"], os.environ["DASHBOARD_PASSWORD"])
XSS_MODE = os.environ.get("SEED_XSS") == "1"
XSS = "<img src=x onerror=__xss=1>"
BEAT_SECONDS = 2
ACK_AFTER_BEATS = 3
DAY = 86400
RULES = {
    "ssh_fail_threshold": 10, "web_login_threshold": 30, "probe_threshold": 10, "exploit_threshold": 3, "scan_ports": 20,
    "max_conn_per_ip": 200, "syn_recv_alert": 500, "max_tracked_ips": 100000, "ssh_ports": [22], "web_ports": [80, 443],
}


def event(rule, ip, action, ports=(), ttl=0, evidence="", simulated=False, ok=True, ago=0):
    return {"rule": rule, "ip": ip, "action": action, "ports": list(ports), "ttl": ttl, "evidence": evidence,
            "simulated": simulated, "ok": ok, "ts": time.time() - ago}


class FakeAgent:
    def __init__(self, name, mode="enforce", max_mode="enforce", config=None, blocks=(), events=(), platform="linux"):
        token = requests.post(f"{BASE}/api/agents/tokens", json={"name": name}, auth=AUTH).json()["token"]
        hostname = "xss-host" if name == XSS else name
        body = requests.post(f"{BASE}/api/agents/enroll", json={"token": token, "hostname": hostname}).json()
        self.node, self.key = body["node_id"], {"X-API-Key": body["api_key"]}
        self.mode, self.max_mode, self.extra, self.platform = mode, max_mode, dict(config or {}), platform
        self.blocks, self.events = list(blocks), list(events)
        self.waiting: list[tuple[int, dict]] = []
        self.beats = 0

    def beat(self):
        self.beats += 1
        ready = [c for due, c in self.waiting if due <= self.beats]
        self.waiting = [(due, c) for due, c in self.waiting if due > self.beats]
        for command in ready:
            self.apply(command)
        answer = requests.post(
            f"{BASE}/api/ingest",
            headers=self.key,
            json={
                "cpu_pct": random.uniform(8, 30), "memory_pct": random.uniform(35, 50), "net_kbps": random.uniform(100, 300),
                "latency_ms": random.uniform(10, 30), "version": XSS if XSS_MODE else "2.0.0",
                "capabilities": {"enforce": self.max_mode == "enforce", "platform": XSS if XSS_MODE else self.platform},
                "config": {"mode": self.mode, "max_mode": self.max_mode, "behind_cdn": False, "rules": RULES, **self.extra},
                "active_blocks": self.blocks,
                "events": self.events,
                "acked_commands": [c["id"] for c in ready],
            },
        )
        answer.raise_for_status()
        self.events = []
        known = {c["id"] for _, c in self.waiting} | {c["id"] for c in ready}
        for command in answer.json()["commands"]:
            if command["id"] not in known:
                self.waiting.append((self.beats + ACK_AFTER_BEATS, command))

    def apply(self, command):
        if command["type"] == "mode":
            self.mode = command["payload"]["mode"]
            if self.mode != "enforce":
                self.blocks = [b for b in self.blocks if b.get("simulated")]
        elif command["type"] == "unblock":
            ip = command["payload"]["ip"]
            self.blocks = [b for b in self.blocks if b["ip"] != ip]


def block(ip, rule, kind, ports=(), left=2800, simulated=False):
    return {"ip": ip, "rule": rule, "ports": list(ports), "until": time.time() + left, "simulated": simulated, "kind": kind}


def agents():
    x = XSS_MODE
    web1_events = [
        event("ssh_bruteforce", "203.0.113.77", "block_port", [22], 3600, "Failed password for root from 203.0.113.77 port 51122 ssh2", ago=900),
        event("web_probe", "198.51.100.23", "block_port", [80, 443], 1800, 'GET /.env HTTP/1.1" 404', ago=1800),
        event("web_exploit", "2001:db8:4f::9", "block_port", [80, 443], 3600, "GET /item?id=1+UNION+SELECT+password+FROM+users", ago=2400),
        event("port_scan", "203.0.113.41", "block_all", (), 900, "connections to 24 closed ports", ago=300),
        event("conn_flood", "203.0.113.140", "rate_limit", (), 600, "412 concurrent connections", ago=200),
        event("distributed_flood", "0.0.0.0", "alert", (), 0, "syn_recv=812 connections=4210 average=390", ago=120),
        event("ssh_bruteforce", "192.0.2.200", "block_port", [22], 3600, "nft add element failed", ok=False, ago=3000),
    ]
    web1_blocks = [
        block("203.0.113.77", "ssh_bruteforce", "block_port", [22]),
        block("198.51.100.23", "web_probe", "block_port", [80, 443], 1400),
        block("2001:db8:4f::", "web_exploit", "block_port", [80, 443], 4300),
        block("203.0.113.41", "port_scan", "block_all", (), 700),
        block("203.0.113.140", "conn_flood", "rate_limit", (), 360),
    ]
    web2_events = [
        event("web_login_bruteforce", "198.51.100.61", "block_port", [80, 443], 900, 'POST /wp-login.php HTTP/1.1" 200', simulated=True, ago=4000),
        event("web_login_bruteforce", "198.51.100.61", "block_port", [80, 443], 900, 'POST /wp-login.php HTTP/1.1" 200', simulated=True, ago=500),
        event("ssh_bruteforce", "203.0.113.18", "block_port", [22], 3600, "Failed password for admin from 203.0.113.18 port 40112 ssh2", simulated=True, ago=800),
        event("conn_flood", "198.51.100.204", "rate_limit", (), 600, "260 concurrent connections", simulated=True, ago=700),
        event("web_exploit", "2001:db8:77::5", "block_port", [80, 443], 3600, "GET /item?id=1+OR+1=1", simulated=True, ago=600),
    ]
    if x:
        web1_events += [
            event(XSS, "203.0.113.90", "block_port", [22], 60, XSS, ago=10),
            event("constructor", "203.0.113.91", "block_port", [22], 60, XSS, ago=20),
            event("__proto__", "203.0.113.92", "alert", (), 0, XSS, ago=30),
        ]
        web1_blocks.append(block("203.0.113.90", XSS, "block_port", [22]))
        web1_blocks.append(block("0.0.0.0", "distributed_flood", "block_all", (), 500))
        web2_events.append(event(XSS, "198.51.100.90", "block_port", [80], 900, XSS, simulated=True, ago=5))
    return [
        FakeAgent(XSS if x else "web-1", events=web1_events, blocks=web1_blocks),
        FakeAgent("api-1", config={"behind_cdn": True}, events=[event("web_probe", "198.51.100.9", "alert", (), 0, "CDN address, alert only", ago=1200)]),
        FakeAgent("web-2", mode="observe", events=web2_events, blocks=[block("198.51.100.61", "web_login_bruteforce", "block_port", [80, 443], simulated=True)]),
        FakeAgent("web-3", mode="observe", max_mode="observe", config={"enforce_rejected": True, "enforce_rejected_reason": XSS if x else "max_mode"}),
        FakeAgent("web-4", mode="enforce", config={"breaker_open": True, "lift_pending": True}),
    ]


def seed_history(live):
    now = time.time()
    with SessionLocal() as db:
        web2 = next(a for a in live if a.node.startswith("web-2"))
        db.get(Agent, web2.node).first_seen = now - 8 * DAY
        db.get(Agent, web2.node).allowlist = ["192.0.2.0/24"]
        web3 = next(a for a in live if a.node.startswith("web-3"))
        db.get(Agent, web3.node).first_seen = now - 2 * DAY
        random.seed(7)
        for a in live:
            for i in range(120):
                ts = now - 30 * (120 - i)
                spike = 70 <= i < 75 and a is live[0]
                db.add(Metric(
                    node_id=a.node, ts=ts, cpu_pct=random.uniform(8, 30) + (55 if spike else 0), memory_pct=random.uniform(35, 50),
                    net_kbps=random.uniform(100, 300) * (6 if spike else 1), latency_ms=random.uniform(10, 30) + (80 if spike else 0),
                    score=random.uniform(.05, .3) + (.6 if spike else 0), is_anomaly=spike,
                ))
        db.add(Anomaly(
            node_id=live[0].node, ts=now - 1500, culprit=XSS if XSS_MODE else "network", severity="warning", cpu_pct=70, memory_pct=44,
            net_kbps=1500, latency_ms=95, ensemble_score=0.91, flags=[],
        ))
        for i in range(40):
            db.add(SecurityEvent(
                node_id=web2.node, ts=now - DAY * (1 + i % 6), rule="ssh_bruteforce", ip=f"203.0.113.{100 + i % 12}", action="block_port",
                ports=[22], ttl=3600, evidence="Failed password for root", simulated=True,
            ))
        db.commit()


def offline_servers():
    now = time.time()
    token = requests.post(f"{BASE}/api/agents/tokens", json={"name": "db-1"}, auth=AUTH).json()["token"]
    db1 = requests.post(f"{BASE}/api/agents/enroll", json={"token": token, "hostname": "db-1"}).json()["node_id"]
    token = requests.post(f"{BASE}/api/agents/tokens", json={"name": "new-1"}, auth=AUTH).json()["token"]
    requests.post(f"{BASE}/api/agents/enroll", json={"token": token, "hostname": "new-1"}).raise_for_status()
    token = requests.post(f"{BASE}/api/agents/tokens", json={"name": "old-1"}, auth=AUTH).json()["token"]
    old = requests.post(f"{BASE}/api/agents/enroll", json={"token": token, "hostname": "old-1"}).json()["node_id"]
    requests.delete(f"{BASE}/api/agents/{old}", auth=AUTH).raise_for_status()
    with SessionLocal() as db:
        agent = db.get(Agent, db1)
        agent.first_seen, agent.last_seen = now - 30 * DAY, now - 720
        agent.config = {"mode": "enforce", "max_mode": "enforce", "rules": RULES}
        agent.capabilities = {"enforce": True, "platform": "linux"}
        agent.mode, agent.max_mode, agent.version = "enforce", "enforce", "2.0.0"
        if XSS_MODE:
            db.add(ActiveBlock(node_id=db1, ip=XSS, rule=XSS, ports=[], until=now + 900, kind="block_all"))
            db.add(SecurityEvent(node_id=db1, ts=now - 2, rule=XSS, ip=XSS, action="block_all", ttl=60, evidence=XSS))
            db.add(SecurityEvent(node_id=db1, ts=now - 3, rule=XSS, ip=XSS, action="block_port", ports=[80], ttl=60, evidence=XSS, simulated=True))
            db.commit()
            agent.config = {**agent.config, "mode": "observe"}
        db.commit()


def main():
    for _ in range(120):
        try:
            requests.get(f"{BASE}/healthz", timeout=1).raise_for_status()
            break
        except requests.RequestException:
            time.sleep(1)
    else:
        sys.exit("backend did not start")
    live = agents()
    for a in live:
        a.beat()
    seed_history(live)
    offline_servers()
    for a in live:
        a.beat()
    open("/tmp/seeded", "w").close()
    while True:
        time.sleep(BEAT_SECONDS)
        for a in live:
            a.beat()


if __name__ == "__main__":
    main()
