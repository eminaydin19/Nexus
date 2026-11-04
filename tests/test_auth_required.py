import base64

import pytest

pytest.importorskip("torch")

from fastapi.testclient import TestClient

from backend.config import Settings
from backend.security import OriginCheckMiddleware

W = {"iforest": 0.25, "lstm": 0.45, "vae": 0.3, "transformer": 0.3}
AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:test-password").decode()}


@pytest.fixture(scope="module")
def app():
    from backend.main import app

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture(scope="module")
def authed(app):
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_app_refuses_to_start_without_password():
    with pytest.raises(RuntimeError):
        Settings(dashboard_user="admin", dashboard_password="").require_dashboard_credentials()
    with pytest.raises(RuntimeError):
        Settings(dashboard_user="", dashboard_password="x").require_dashboard_credentials()
    Settings(dashboard_user="admin", dashboard_password="x").require_dashboard_credentials()


@pytest.mark.parametrize(
    "method,path",
    [("POST", "/api/retrain"), ("POST", "/api/weights"), ("GET", "/api/agents"), ("GET", "/metrics")],
)
def test_admin_routes_require_auth(client, method, path):
    assert client.request(method, path).status_code == 401


def test_exempt_paths_stay_open(client):
    assert client.get("/healthz").status_code == 200
    assert client.post("/api/ingest").status_code == 401  # API key, not Basic auth


def test_cross_origin_post_rejected(authed):
    r = authed.post("/api/weights", json=W, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_same_origin_and_originless_post_pass(authed):
    assert authed.post("/api/weights", json=W, headers={"Origin": "http://testserver"}).status_code == 200
    assert authed.post("/api/weights", json=W).status_code == 200


def test_cross_origin_get_is_not_blocked(authed):
    assert authed.get("/api/nodes", headers={"Origin": "https://evil.example"}).status_code == 200


def _origin_client(trust_proxy):
    from fastapi import FastAPI

    app = FastAPI()
    app.add_middleware(OriginCheckMiddleware, trust_proxy=trust_proxy)
    app.post("/x")(lambda: {})
    return TestClient(app)


def test_forwarded_host_only_trusted_behind_proxy():
    h = {"Origin": "https://nexus.example", "X-Forwarded-Host": "nexus.example"}
    assert _origin_client(True).post("/x", headers=h).status_code == 200
    assert _origin_client(False).post("/x", headers=h).status_code == 403


def test_ingest_requires_basic_auth_when_no_api_key():
    from fastapi import FastAPI

    from backend.main import basic_exempt_paths
    from backend.security import BasicAuthMiddleware

    cfg = Settings(dashboard_user="admin", dashboard_password="x", ingest_api_key="")
    assert "/api/ingest" not in basic_exempt_paths(cfg)
    app = FastAPI()
    app.add_middleware(BasicAuthMiddleware, username="admin", password="x", exempt_paths=basic_exempt_paths(cfg))
    app.post("/api/ingest")(lambda: {})
    assert TestClient(app).post("/api/ingest").status_code == 401
