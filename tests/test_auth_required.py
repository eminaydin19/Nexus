import base64

import pytest

pytest.importorskip("torch")

from fastapi.testclient import TestClient

from backend.config import Settings
from backend.security import OriginCheckMiddleware

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
    [("POST", "/api/retrain"), ("POST", "/api/agents/tokens"), ("GET", "/api/agents"), ("GET", "/metrics")],
)
def test_admin_routes_require_auth(client, method, path):
    assert client.request(method, path).status_code == 401


def test_exempt_paths_stay_open(client):
    assert client.get("/healthz").status_code == 200
    r = client.post("/api/ingest")
    assert r.status_code == 401 and "WWW-Authenticate" not in r.headers
    assert r.json() == {"detail": "invalid or missing API key"}
    assert client.post("/api/agents/enroll", json={"token": "x", "hostname": "h"}).status_code == 401


def test_cross_origin_post_rejected(authed):
    r = authed.post("/api/agents/tokens", json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_same_origin_and_originless_post_pass(authed):
    assert authed.post("/api/agents/tokens", json={}, headers={"Origin": "http://testserver"}).status_code == 200
    assert authed.post("/api/agents/tokens", json={}).status_code == 200


def test_cross_origin_get_is_not_blocked(authed):
    assert authed.get("/api/nodes", headers={"Origin": "https://evil.example"}).status_code == 200


def _origin_client(trust_proxy):
    from fastapi import FastAPI

    app = FastAPI()
    app.add_middleware(OriginCheckMiddleware, trust_proxy=trust_proxy)
    app.post("/x")(lambda: {})
    return TestClient(app)


def test_origin_check_tolerates_proxy_host_list_and_case():
    h = {"Origin": "https://Nexus.Example", "X-Forwarded-Host": "nexus.example, internal.lan"}
    assert _origin_client(True).post("/x", headers=h).status_code == 200
    h = {"Origin": "https://evil.example", "X-Forwarded-Host": "nexus.example, evil.example"}
    assert _origin_client(True).post("/x", headers=h).status_code == 403


def test_forwarded_host_only_trusted_behind_proxy():
    h = {"Origin": "https://nexus.example", "X-Forwarded-Host": "nexus.example"}
    assert _origin_client(True).post("/x", headers=h).status_code == 200
    assert _origin_client(False).post("/x", headers=h).status_code == 403
