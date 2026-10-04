import numpy as np
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.explain import contributions
from backend.security import ApiKeyMiddleware, RateLimitMiddleware, client_ip


def _app(*layers):
    app = FastAPI()
    for layer, kwargs in layers:
        app.add_middleware(layer, **kwargs)
    app.post("/api/ingest")(lambda: {"ok": True})
    app.get("/api/nodes")(lambda: {"ok": True})
    return app


def test_api_key_required_for_ingest():
    client = TestClient(_app((ApiKeyMiddleware, {"api_key": "s3cret"})))
    assert client.post("/api/ingest").status_code == 401
    assert client.post("/api/ingest", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/ingest", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.post("/api/ingest", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_api_key_does_not_touch_other_paths():
    client = TestClient(_app((ApiKeyMiddleware, {"api_key": "s3cret"})))
    assert client.get("/api/nodes").status_code == 200


def test_rate_limit_returns_429_with_retry_after():
    client = TestClient(_app((RateLimitMiddleware, {"per_minute": 3})))
    assert [client.get("/api/nodes").status_code for _ in range(3)] == [200, 200, 200]
    blocked = client.get("/api/nodes")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1


def test_rate_limit_window_slides_and_isolates_clients():
    limiter = RateLimitMiddleware(app=None, per_minute=2, window=10)
    assert limiter.check("a", now=0) is None
    assert limiter.check("a", now=1) is None
    assert limiter.check("a", now=2) is not None
    assert limiter.check("b", now=2) is None
    assert limiter.check("a", now=11.5) is None


def test_rate_limit_zero_disables():
    client = TestClient(_app((RateLimitMiddleware, {"per_minute": 0})))
    assert all(client.get("/api/nodes").status_code == 200 for _ in range(20))


def test_client_ip_only_trusts_forwarded_header_when_enabled():
    scope = {"client": ("10.1.1.1", 1234), "headers": [(b"x-forwarded-for", b"6.6.6.6, 203.0.113.9")]}
    assert client_ip(scope) == "10.1.1.1"
    assert client_ip(scope, trust_proxy=True) == "203.0.113.9"
    assert client_ip({"client": None, "headers": []}) == "unknown"


def test_contributions_sum_to_one_and_rank_largest_deviation():
    result = contributions(np.array([0.1, 0.1, 6.0, 0.2]))
    assert abs(sum(result.values()) - 1.0) < 1e-3
    assert max(result, key=result.get) == "network"


def test_contributions_handle_zero_vector():
    result = contributions(np.zeros(4))
    assert set(result.values()) == {0.25}
