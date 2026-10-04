import base64
import secrets

from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send


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
        if scope["type"] not in ("http", "websocket") or scope["path"] in self._exempt or self._authorized(scope):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return
        response = Response("Unauthorized", status_code=401, headers={"WWW-Authenticate": 'Basic realm="Nexus"'})
        await response(scope, receive, send)
