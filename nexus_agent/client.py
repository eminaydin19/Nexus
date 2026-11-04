from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

import requests

INGEST_PATH = "/api/ingest"
ENROLL_PATH = "/api/agents/enroll"
TIMEOUT = (5, 15)


class ClientError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Command:
    id: int
    type: str
    payload: dict = field(default_factory=dict)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _base_url(url: str, allow_insecure: bool) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("central URL must be http(s)://host")
    if parts.username or parts.password:
        raise ValueError("central URL must not contain credentials")
    if parts.scheme != "https" and not allow_insecure and not _is_loopback(parts.hostname):
        raise ValueError("central URL must use https unless it is loopback or insecure mode is set")
    # Older env files hold the full ingest URL.
    path = parts.path.rstrip("/")
    if path.endswith(INGEST_PATH):
        path = path[: -len(INGEST_PATH)]
    return "%s://%s%s" % (parts.scheme, parts.netloc, path)


def _parse_commands(items: object) -> List[Command]:
    out = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        cid, kind, payload = item.get("id"), item.get("type"), item.get("payload")
        if isinstance(cid, int) and not isinstance(cid, bool) and isinstance(kind, str):
            out.append(Command(cid, kind, payload if isinstance(payload, dict) else {}))
    return out


class Client:
    def __init__(self, url: str, key: str, allow_insecure: bool = False):
        self._url = _base_url(url, allow_insecure) + INGEST_PATH
        key = key.strip() if isinstance(key, str) else ""
        # requests quotes a bad header value in its exception, which would put the key in the log.
        if not key or not key.isascii() or not key.isprintable():
            raise ValueError("invalid API key")
        self._session = requests.Session()
        self._session.headers["X-API-Key"] = key
        self._session.verify = True

    def send(self, payload: dict) -> List[Command]:
        try:
            r = self._session.post(self._url, json=payload, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as exc:
            raise ClientError("central unreachable: %s" % type(exc).__name__) from None
        if r.status_code != 200:
            raise ClientError("central answered HTTP %d" % r.status_code, r.status_code)
        try:
            body = r.json()
        except ValueError:
            raise ClientError("central answered with invalid JSON") from None
        return _parse_commands(body.get("commands") if isinstance(body, dict) else None)

    @staticmethod
    def enroll(url: str, token: str, hostname: str, allow_insecure: bool = False) -> Tuple[str, str]:
        target = _base_url(url, allow_insecure) + ENROLL_PATH
        try:
            r = requests.post(target, json={"token": token, "hostname": hostname[:255]}, timeout=TIMEOUT,
                              allow_redirects=False, verify=True)
        except requests.RequestException as exc:
            raise ClientError("central unreachable: %s" % type(exc).__name__) from None
        if r.status_code != 200:
            raise ClientError("enrollment refused: HTTP %d" % r.status_code, r.status_code)
        try:
            body = r.json()
            node_id, api_key = body["node_id"], body["api_key"]
        except (ValueError, KeyError, TypeError):
            raise ClientError("invalid enrollment response") from None
        if not isinstance(node_id, str) or not isinstance(api_key, str):
            raise ClientError("invalid enrollment response")
        return node_id, api_key
