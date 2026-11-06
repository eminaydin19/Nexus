from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nexus_agent.client import Client, ClientError, Command

KEY = "secret-key-value"


class Server:
    def __init__(self):
        self.requests, self.status, self.body, self.headers = [], 200, b'{"commands": []}', {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append((self.path, dict(self.headers), json.loads(raw)))
                self.send_response(outer.status)
                for k, v in outer.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.httpd.shutdown()


@pytest.mark.parametrize("url", ["http://nexus.example.com", "http://localhost.evil.com", "http://127.0.0.1@evil.com/",
                                 "ftp://127.0.0.1", "nexus.example.com", ""])
def test_client_refuses_http_unless_loopback_or_insecure(url):
    with pytest.raises(ValueError):
        Client(url, KEY)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000",
                                 "https://nexus.example.com"])
def test_client_accepts_https_and_loopback(url):
    Client(url, KEY)


def test_allow_insecure_permits_http_but_tls_verification_stays_on():
    client = Client("http://nexus.example.com", KEY, allow_insecure=True)
    assert client._session.verify is True
    assert Client("https://nexus.example.com", KEY, allow_insecure=True)._session.verify is True


def test_invalid_key_is_refused_without_echoing_it():
    with pytest.raises(ValueError) as exc:
        Client("https://nexus.example.com", "bad\nkey")
    assert "bad" not in str(exc.value)
    with pytest.raises(ValueError):
        Client("https://nexus.example.com", "  ")


def test_key_whitespace_from_env_file_is_stripped(server):
    Client(server.url, KEY + "\r\n").send({})
    assert server.requests[0][1]["X-API-Key"] == KEY


def test_url_userinfo_is_refused():
    with pytest.raises(ValueError):
        Client("https://u:p@nexus.example.com", KEY)


@pytest.mark.parametrize("suffix", ["", "/", "/api/ingest", "/api/ingest/"])
def test_send_posts_to_ingest_with_auth_header(server, suffix):
    server.body = json.dumps({"commands": [{"id": 3, "type": "unblock", "payload": {"ip": "203.0.113.9"}}]}).encode()
    cmds = Client(server.url + suffix, KEY).send({"cpu_pct": 1})
    path, headers, body = server.requests[0]
    assert path == "/api/ingest"
    assert headers["X-API-Key"] == KEY
    assert body == {"cpu_pct": 1}
    assert cmds == [Command(3, "unblock", {"ip": "203.0.113.9"})]


def test_redirect_is_not_followed_so_the_key_stays_home(server):
    other = Server()
    try:
        server.status, server.headers = 302, {"Location": other.url + "/api/ingest"}
        with pytest.raises(ClientError) as exc:
            Client(server.url, KEY).send({})
        assert exc.value.status == 302
        assert other.requests == []
    finally:
        other.httpd.shutdown()


def test_error_status_and_bad_json_raise(server):
    client = Client(server.url, KEY)
    server.status = 422
    with pytest.raises(ClientError) as exc:
        client.send({})
    assert exc.value.status == 422
    server.status, server.body = 200, b"<html>"
    with pytest.raises(ClientError):
        client.send({})


def test_unreachable_central_raises_client_error_without_key():
    with pytest.raises(ClientError) as exc:
        Client("http://127.0.0.1:1", KEY).send({})
    assert KEY not in str(exc.value)


def test_malformed_commands_are_filtered(server):
    server.body = json.dumps({"commands": [
        "nope", {"type": "unblock"}, {"id": True, "type": "mode"}, {"id": 1, "type": 7},
        {"id": 2, "type": "mode", "payload": "x"},
    ]}).encode()
    assert Client(server.url, KEY).send({}) == [Command(2, "mode", {})]
    server.body = b'{"commands": "x"}'
    assert Client(server.url, KEY).send({}) == []


def test_enroll_returns_identity(server):
    server.body = b'{"node_id": "web-1", "api_key": "k2"}'
    assert Client.enroll(server.url, "tok", "web-1") == ("web-1", "k2")
    path, _, body = server.requests[0]
    assert path == "/api/agents/enroll"
    assert body == {"token": "tok", "hostname": "web-1"}


def test_enroll_refuses_http_and_does_not_follow_redirects(server):
    with pytest.raises(ValueError):
        Client.enroll("http://nexus.example.com", "tok", "h")
    other = Server()
    try:
        server.status, server.headers = 307, {"Location": other.url + "/api/agents/enroll"}
        with pytest.raises(ClientError):
            Client.enroll(server.url, "tok", "h")
        assert other.requests == []
    finally:
        other.httpd.shutdown()


def test_enroll_failure_does_not_echo_the_token(server):
    server.status = 401
    with pytest.raises(ClientError) as exc:
        Client.enroll(server.url, "tok-secret", "h")
    assert "tok-secret" not in str(exc.value)
    server.status, server.body = 200, b'{"node_id": 1}'
    with pytest.raises(ClientError):
        Client.enroll(server.url, "tok-secret", "h")
