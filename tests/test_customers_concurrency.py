"""Against a real uvicorn, because the lost updates only show up with real concurrent requests."""

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("torch")
requests = pytest.importorskip("requests")

AUTH = ("admin", "race-test")
METRICS = {"cpu_pct": 1.0, "memory_pct": 2.0, "net_kbps": 3.0, "latency_ms": 4.0}


@pytest.fixture(scope="module")
def base():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = {
        **os.environ, "DATA_DIR": tempfile.mkdtemp(prefix="nexus-race-"), "DATABASE_URL": "", "DASHBOARD_USER": AUTH[0],
        "DASHBOARD_PASSWORD": AUTH[1], "RATE_LIMIT_PER_MINUTE": "0", "SLACK_WEBHOOK_URL": "",
    }
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--port", str(port), "--workers", "1", "--log-level", "warning"],
        env=env, cwd=Path(__file__).resolve().parent.parent,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(240):
            try:
                requests.get(f"{url}/healthz", timeout=1).raise_for_status()
                break
            except requests.RequestException:
                time.sleep(0.25)
        else:
            pytest.fail("uvicorn did not start")
        yield url
    finally:
        server.terminate()
        server.wait(timeout=20)


def enroll(base, name):
    token = requests.post(f"{base}/api/agents/tokens", json={"name": name}, auth=AUTH).json()["token"]
    body = requests.post(f"{base}/api/agents/enroll", json={"token": token, "hostname": name}).json()
    return body["node_id"], {"X-API-Key": body["api_key"]}


def parallel(jobs):
    start = threading.Barrier(len(jobs))
    results = [None] * len(jobs)

    def run(i, job):
        start.wait()
        results[i] = job()

    threads = [threading.Thread(target=run, args=(i, job)) for i, job in enumerate(jobs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def agents(base):
    return requests.get(f"{base}/api/agents", auth=AUTH).json()["agents"]


def test_parallel_customers_lose_nothing(base):
    nodes = [enroll(base, f"race-{i}") for i in range(4)]
    wanted = set()
    for round_no in range(6):
        ips = [f"100.64.{round_no}.{i}" for i in range(1, 9)]
        wanted |= {f"{ip}/32" for ip in ips}
        answers = parallel([
            (lambda ip=ip: requests.post(f"{base}/api/customers", json={"ip": ip}, auth=AUTH)) for ip in ips
        ])
        assert [a.status_code for a in answers] == [200] * 8
        assert all(not a.json()["failed"] for a in answers)
    for agent in agents(base):
        assert wanted <= set(agent["allowlist"]), agent["node_id"]
    # What the agent ends up applying must hold everything too, not only the database.
    for node, key in nodes:
        commands = requests.post(f"{base}/api/ingest", json=METRICS, headers=key).json()["commands"]
        last = [c for c in commands if c["type"] == "allowlist"][-1]
        assert wanted <= set(last["payload"]["ips"]), node


def test_settings_write_and_customers_do_not_clobber_each_other(base):
    node, _ = enroll(base, "race-put")
    current = next(a for a in agents(base) if a["node_id"] == node)["allowlist"]
    put = lambda: requests.put(f"{base}/api/agents/{node}/allowlist", json=[*current, "198.18.0.0/24"], auth=AUTH)
    posts = [(lambda i=i: requests.post(f"{base}/api/customers", json={"ip": f"100.65.0.{i}"}, auth=AUTH)) for i in range(1, 8)]
    answers = parallel([put, *posts])
    assert [a.status_code for a in answers] == [200] * 8
    allowlist = next(a for a in agents(base) if a["node_id"] == node)["allowlist"]
    # The PUT replaces the list by design, so only customers that came after it survive; none may be half-applied.
    assert len(allowlist) == len(set(allowlist))
    final = requests.post(f"{base}/api/customers", json={"ip": "100.65.0.99"}, auth=AUTH)
    assert final.status_code == 200
    assert set(allowlist) <= set(next(a for a in agents(base) if a["node_id"] == node)["allowlist"])
