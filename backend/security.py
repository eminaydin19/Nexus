import base64
import secrets
import time
from collections import deque
from urllib.parse import urlsplit

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from backend.metrics import counters


def client_ip(scope: Scope, trust_proxy: bool = False) -> str:
    """Best-effort client address. Only trusts X-Forwarded-For when explicitly enabled."""
    if trust_proxy:
        forwarded = dict(scope.get("headers", [])).get(b"x-forwarded-for", b"").decode("latin-1")
        # The last hop is the one appended by our own proxy; earlier entries are client-controlled.
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-1]
    client = scope.get("client")
    return client[0] if client else "unknown"


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class SecurityHeadersMiddleware:
    """Attacker text from logs reaches the panel, so a rendering mistake must still be unable to execute."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
                headers["X-Content-Type-Options"] = "nosniff"
            await send(message)

        await self.app(scope, receive, with_headers)


class RateLimitMiddleware:
    """Sliding-window limiter keyed by client IP. In-memory, so single-process only."""

    def __init__(
        self,
        app: ASGIApp,
        per_minute: int,
        trust_proxy: bool = False,
        exempt_paths: tuple[str, ...] = ("/healthz",),
        window: float = 60.0,
    ):
        self.app = app
        self.limit = per_minute
        self.trust_proxy = trust_proxy
        self.exempt = exempt_paths
        self.window = window
        self._hits: dict[str, deque] = {}
        self._last_sweep = time.monotonic()

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < self.window:
            return
        self._last_sweep = now
        for key in [k for k, q in self._hits.items() if not q or now - q[-1] > self.window]:
            del self._hits[key]

    def check(self, key: str, now: float | None = None) -> float | None:
        """Record a hit. Returns seconds to wait when over budget, otherwise None."""
        now = time.monotonic() if now is None else now
        self._sweep(now)
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return max(1.0, self.window - (now - hits[0]))
        hits.append(now)
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.limit <= 0 or scope["path"] in self.exempt:
            await self.app(scope, receive, send)
            return
        retry_after = self.check(client_ip(scope, self.trust_proxy))
        if retry_after is not None:
            counters.inc("nexus_rate_limited_total")
            response = JSONResponse(
                {"detail": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(int(retry_after))},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class BasicAuthMiddleware:
    def __init__(self, app: ASGIApp, username: str, password: str, exempt_paths: tuple[str, ...] = ()):
        self.app = app
        self._username = username.encode()
        self._password = password.encode()
        self._exempt = exempt_paths

    def _authorized(self, scope: Scope) -> bool:
        header = dict(scope["headers"]).get(b"authorization", b"").decode("latin-1")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            user, _, password = base64.b64decode(token).decode("utf-8").partition(":")
        except ValueError:
            return False
        user_ok = secrets.compare_digest(user.encode(), self._username)
        password_ok = secrets.compare_digest(password.encode(), self._password)
        return user_ok and password_ok

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan" or (scope["type"] == "http" and (scope["path"] in self._exempt or self._authorized(scope))):
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        response = Response("Unauthorized", status_code=401, headers={"WWW-Authenticate": 'Basic realm="Nexus"'})
        await response(scope, receive, send)


class OriginCheckMiddleware:
    """CSRF guard: rejects state-changing requests whose Origin host differs from the request host.

    Requests without Origin (agents, curl) pass; browsers always send it on cross-site writes.
    """

    UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(self, app: ASGIApp, trust_proxy: bool = False):
        self.app = app
        self.trust_proxy = trust_proxy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] in self.UNSAFE:
            headers = dict(scope["headers"])
            origin = headers.get(b"origin", b"").decode("latin-1")
            host = headers.get(b"host", b"")
            if self.trust_proxy:
                host = headers.get(b"x-forwarded-host", host)
            if origin and urlsplit(origin).netloc != host.decode("latin-1"):
                counters.inc("nexus_auth_failures_total")
                await JSONResponse({"detail": "cross-origin request rejected"}, status_code=403)(scope, receive, send)
                return
        await self.app(scope, receive, send)
