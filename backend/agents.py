import hashlib
import ipaddress
import re
import secrets
import threading
import time
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.commands import enqueue
from backend.config import settings
from backend.db import Agent, AgentCommand, EnrollToken, SessionLocal
from backend.metrics import counters

MODES = ("off", "observe", "enforce")
MAX_ALLOWLIST = 1000
NODE_ID_PATTERN = r"^[A-Za-z0-9._:@-]+$"
_UNSAFE = re.compile(r"[^A-Za-z0-9._:@-]")
_ENROLL_ATTEMPTS = 5
OFFLINE_AFTER_SECONDS = 90
ALLOWLIST_LOCK = threading.Lock()


class InvalidToken(Exception):
    pass


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def create_enroll_token(db: Session, name: str, ttl: int = 86400) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    db.add(EnrollToken(token_hash=_hash(token), name=name, created_at=now, expires_at=now + ttl))
    db.commit()
    return token


def _node_id(db: Session, hostname: str) -> str:
    base = _UNSAFE.sub("-", hostname).strip("-")[:100] or "node"
    node_id = base
    while db.get(Agent, node_id):
        node_id = f"{base}-{secrets.token_hex(2)}"
    return node_id


def enroll(db: Session, token: str, hostname: str) -> tuple[str, str]:
    token_hash = _hash(token)
    for _ in range(_ENROLL_ATTEMPTS):
        now = time.time()
        claimed = db.execute(
            update(EnrollToken)
            .where(
                EnrollToken.token_hash == token_hash,
                EnrollToken.used_at.is_(None),
                EnrollToken.expires_at > now,
            )
            .values(used_at=now)
        )
        if claimed.rowcount != 1:
            db.rollback()
            raise InvalidToken
        name = db.get(EnrollToken, token_hash).name
        api_key = secrets.token_urlsafe(32)
        node_id = _node_id(db, hostname)
        db.add(Agent(node_id=node_id, name=name, key_hash=_hash(api_key), created_at=now))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            continue
        return node_id, api_key
    raise RuntimeError("could not allocate a node_id")


def authenticate(db: Session, api_key: str) -> Agent | None:
    digest = _hash(api_key)
    agent = db.query(Agent).filter(Agent.key_hash == digest).first()
    if agent is None or agent.revoked_at is not None:
        return None
    return agent if secrets.compare_digest(agent.key_hash, digest) else None


def revoke(db: Session, node_id: str) -> bool:
    agent = db.get(Agent, node_id)
    if agent is None:
        return False
    if agent.revoked_at is None:
        agent.revoked_at = time.time()
        db.commit()
    return True


def touch(db: Session, agent: Agent) -> None:
    now = time.time()
    agent.first_seen = agent.first_seen or now
    agent.last_seen = now
    db.commit()


def pending_by_node(db: Session) -> dict[str, list[dict]]:
    rows = db.query(AgentCommand).filter(AgentCommand.acked_at.is_(None)).order_by(AgentCommand.id)
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r.node_id, []).append({"id": r.id, "type": r.type, "payload": r.payload, "created_at": r.created_at})
    return out


def _status(agent: Agent, now: float) -> str:
    if agent.revoked_at is not None:
        return "revoked"
    if agent.last_seen is None:
        return "never"
    return "online" if now - agent.last_seen <= OFFLINE_AFTER_SECONDS else "offline"


def server_view(agent: Agent, now: float, pending_commands: dict[str, list[dict]]) -> dict:
    reported = (agent.config or {}).get("mode")
    return {
        **agent.as_dict(),
        "status": _status(agent, now),
        "reported_mode": reported if reported in MODES else agent.mode,
        "pending": pending_commands.get(agent.node_id, []),
    }


def _db():
    with SessionLocal() as db:
        yield db


def require_agent(
    db: Session = Depends(_db),
    x_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
) -> Agent:
    scheme, _, bearer = authorization.partition(" ")
    key = x_api_key or (bearer if scheme.lower() == "bearer" else "")
    agent = authenticate(db, key) if key else None
    if agent is None:
        counters.inc("nexus_auth_failures_total")
        raise HTTPException(401, "invalid or missing API key")
    return agent


router = APIRouter(prefix="/api/agents")


class TokenRequest(BaseModel):
    name: str = Field(default="", max_length=128)


class EnrollRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256)
    hostname: str = Field(min_length=1, max_length=255)


@router.post("/enroll")
def enroll_agent(body: EnrollRequest, db: Session = Depends(_db)):
    try:
        node_id, api_key = enroll(db, body.token, body.hostname)
    except InvalidToken:
        counters.inc("nexus_auth_failures_total")
        raise HTTPException(401, "invalid enrollment token") from None
    return {"node_id": node_id, "api_key": api_key}


@router.post("/tokens")
def create_token(body: TokenRequest, db: Session = Depends(_db)):
    return {"token": create_enroll_token(db, body.name), "expires_in": 86400, "public_url": settings.public_url}


@router.get("")
def list_agents(db: Session = Depends(_db)):
    now, commands = time.time(), pending_by_node(db)
    return {"agents": [server_view(a, now, commands) for a in db.query(Agent).order_by(Agent.created_at)]}


@router.delete("/{node_id}")
def revoke_agent(node_id: str, db: Session = Depends(_db)):
    if not revoke(db, node_id):
        raise HTTPException(404, "unknown agent")
    return {"status": "ok"}


class ModeRequest(BaseModel):
    mode: Literal["off", "observe", "enforce"]


class UnblockRequest(BaseModel):
    ip: str = Field(max_length=45)


def _agent_or_404(db: Session, node_id: str, for_update: bool = False) -> Agent:
    agent = db.get(Agent, node_id, with_for_update=for_update)
    if agent is None:
        raise HTTPException(404, "unknown agent")
    return agent


@router.post("/{node_id}/unblock")
def unblock(node_id: str, body: UnblockRequest, db: Session = Depends(_db)):
    _agent_or_404(db, node_id)
    try:
        ip = str(ipaddress.ip_address(body.ip))
    except ValueError:
        raise HTTPException(400, "invalid IP address") from None
    return {"status": "ok", "command_id": enqueue(db, node_id, "unblock", {"ip": ip})}


@router.put("/{node_id}/allowlist")
def set_allowlist(node_id: str, body: list[str], db: Session = Depends(_db)):
    if len(body) > MAX_ALLOWLIST:
        raise HTTPException(400, f"at most {MAX_ALLOWLIST} entries")
    try:
        entries = [str(ipaddress.ip_network(item, strict=False)) for item in body]
    except ValueError:
        raise HTTPException(400, "invalid IP or CIDR in allowlist") from None
    with ALLOWLIST_LOCK:
        agent = _agent_or_404(db, node_id, for_update=True)
        agent.allowlist = entries
        return {"status": "ok", "command_id": enqueue(db, node_id, "allowlist", {"ips": entries})}


@router.put("/{node_id}/mode")
def set_mode(node_id: str, body: ModeRequest, db: Session = Depends(_db)):
    agent = _agent_or_404(db, node_id)
    if MODES.index(body.mode) > MODES.index(agent.max_mode):
        raise HTTPException(409, f"mode exceeds the agent's max_mode ({agent.max_mode})")
    agent.mode = body.mode
    return {"status": "ok", "command_id": enqueue(db, node_id, "mode", {"mode": body.mode})}
