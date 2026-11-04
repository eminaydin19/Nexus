import hashlib
import re
import secrets
import time

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db import Agent, EnrollToken, SessionLocal
from backend.metrics import counters

NODE_ID_PATTERN = r"^[A-Za-z0-9._:@-]+$"
_UNSAFE = re.compile(r"[^A-Za-z0-9._:@-]")
_ENROLL_ATTEMPTS = 5


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
        # The conditional UPDATE is the single-use gate: only one concurrent caller sees rowcount 1.
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
            # Another enrollment took the same node_id between check and insert; retry with a new suffix.
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
    return {"token": create_enroll_token(db, body.name), "expires_in": 86400}


@router.get("")
def list_agents(db: Session = Depends(_db)):
    return {"agents": [a.as_dict() for a in db.query(Agent).order_by(Agent.created_at)]}


@router.delete("/{node_id}")
def revoke_agent(node_id: str, db: Session = Depends(_db)):
    if not revoke(db, node_id):
        raise HTTPException(404, "unknown agent")
    return {"status": "ok"}
