"""Read models for the web panel, plus the one write that spans every server."""

import ipaddress
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.agents import MAX_ALLOWLIST, _agent_or_404, _db, pending_by_node, server_view
from backend.commands import enqueue
from backend.db import ActiveBlock, Agent, Anomaly, SecurityEvent

BLOCK_ACTIONS = ("block_port", "block_all")
DAY_SECONDS = 86400
WATCH_DAYS = 7
RECENT_LIMIT = 10
MAX_WATCH_ITEMS = 200

router = APIRouter(prefix="/api")


def _network(ip: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The range a block on this address covers. None for text that is not an address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return ipaddress.ip_network(f"{addr}/{64 if addr.version == 6 else 32}", strict=False)


def _covered(network, allowlist: list[str]) -> bool:
    if network is None:
        return False
    entries = (ipaddress.ip_network(item, strict=False) for item in allowlist)
    return any(e.version == network.version and network.subnet_of(e) for e in entries)


def _live_agents(db: Session) -> list[Agent]:
    return db.query(Agent).filter(Agent.revoked_at.is_(None)).order_by(Agent.created_at).all()


def recent_events(db: Session, limit: int, node=None, rule=None, actions=None, simulated=None) -> list[dict]:
    query = db.query(SecurityEvent)
    for column, value in ((SecurityEvent.node_id, node), (SecurityEvent.rule, rule), (SecurityEvent.simulated, simulated)):
        if value is not None:
            query = query.filter(column == value)
    if actions:
        query = query.filter(SecurityEvent.action.in_(actions))
    return [row.as_dict() for row in query.order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(limit)]


@router.get("/events")
def events(
    node: str | None = None,
    rule: str | None = None,
    action: Annotated[list[str] | None, Query()] = None,
    simulated: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(_db),
):
    return {"events": recent_events(db, limit, node, rule, action, simulated)}


def _evidence_by_block(db: Session, now: float) -> dict[tuple, str]:
    # Blocks live at most a day, so a day of events holds the line behind each one; ascending ts leaves the newest.
    rows = (
        db.query(SecurityEvent.node_id, SecurityEvent.rule, SecurityEvent.ip, SecurityEvent.evidence)
        .filter(SecurityEvent.ts >= now - DAY_SECONDS)
        .order_by(SecurityEvent.ts, SecurityEvent.id)
    )
    return {(node, rule, _network(ip)): evidence for node, rule, ip, evidence in rows}


def active_blocks(db: Session, now: float, simulated: bool | None = None) -> list[dict]:
    query = (
        db.query(ActiveBlock)
        .join(Agent, Agent.node_id == ActiveBlock.node_id)
        .filter(Agent.revoked_at.is_(None), ActiveBlock.until > now)
    )
    if simulated is not None:
        query = query.filter(ActiveBlock.simulated == simulated)
    return [b.as_dict() for b in query.order_by(ActiveBlock.node_id, ActiveBlock.until)]


@router.get("/blocks")
def blocks(simulated: bool | None = None, db: Session = Depends(_db)):
    now = time.time()
    evidence = _evidence_by_block(db, now)
    removals = {
        (node, c["payload"].get("ip"))
        for node, commands in pending_by_node(db).items()
        for c in commands
        if c["type"] == "unblock"
    }
    rows = active_blocks(db, now, simulated)
    for row in rows:
        row["evidence"] = evidence.get((row["node_id"], row["rule"], _network(row["ip"])), "")
        row["pending_removal"] = (row["node_id"], row["ip"]) in removals
    return {"blocks": rows}


def watch_summary(db: Session, agent: Agent, now: float, pending_commands: list[dict]) -> dict:
    groups = (
        db.query(
            SecurityEvent.ip,
            SecurityEvent.rule,
            SecurityEvent.action,
            func.count().label("count"),
            func.max(SecurityEvent.id).label("last_id"),
        )
        .filter(
            SecurityEvent.node_id == agent.node_id,
            SecurityEvent.simulated.is_(True),
            SecurityEvent.action != "alert",
            SecurityEvent.ts >= now - WATCH_DAYS * DAY_SECONDS,
        )
        .group_by(SecurityEvent.ip, SecurityEvent.rule, SecurityEvent.action)
        .all()
    )
    by_rule: dict[str, int] = {}
    for group in groups:
        by_rule[group.rule] = by_rule.get(group.rule, 0) + group.count

    newest = sorted(groups, key=lambda g: g.last_id, reverse=True)
    allowlist_pending = any(c["type"] == "allowlist" for c in pending_commands)
    items = []
    for group in newest:
        covered = _covered(_network(group.ip), agent.allowlist or [])
        if covered and not allowlist_pending:
            continue
        if len(items) < MAX_WATCH_ITEMS:
            event = db.get(SecurityEvent, group.last_id)
            items.append(
                {
                    "ip": group.ip,
                    "rule": group.rule,
                    "action": group.action,
                    "count": group.count,
                    "last_ts": event.ts,
                    "ports": event.ports or [],
                    "ttl": event.ttl,
                    "evidence": event.evidence,
                    "pending": covered,
                }
            )
    first_seen = agent.first_seen
    return {
        "node_id": agent.node_id,
        "window_days": WATCH_DAYS,
        "would_block": sum(g.count for g in groups if g.action in BLOCK_ACTIONS),
        "would_slow": sum(g.count for g in groups if g.action == "rate_limit"),
        "addresses": len({g.ip for g in groups}),
        "by_rule": [{"rule": r, "count": n} for r, n in sorted(by_rule.items(), key=lambda kv: -kv[1])],
        "watched_days": int((now - first_seen) // DAY_SECONDS) if first_seen else 0,
        "ready": bool(first_seen and now - first_seen >= WATCH_DAYS * DAY_SECONDS),
        "items": items,
    }


def _watching(db: Session, now: float, commands: dict[str, list[dict]]) -> list[dict]:
    out = []
    for agent in _live_agents(db):
        view = server_view(agent, now, commands)
        if view["reported_mode"] == "observe" and view["status"] != "never":
            out.append({**watch_summary(db, agent, now, view["pending"]), "server": view})
    return out


@router.get("/watch")
def watch_all(db: Session = Depends(_db)):
    return {"servers": _watching(db, time.time(), pending_by_node(db))}


@router.get("/watch/{node_id}")
def watch_one(node_id: str, db: Session = Depends(_db)):
    agent = _agent_or_404(db, node_id)
    return watch_summary(db, agent, time.time(), pending_by_node(db).get(node_id, []))


def _attention(view: dict, now: float) -> list[dict]:
    def item(kind: str, **extra) -> dict:
        return {"type": kind, "node_id": view["node_id"], "name": view["name"], **extra}

    if view["status"] in ("offline", "never"):
        # An offline agent's last report is stale, so only the silence itself is worth a call.
        return [item("offline", last_seen=view["last_seen"], created_at=view["created_at"])]
    config = view["config"] or {}
    found = []
    if config.get("enforce_rejected"):
        found.append(item("enforce_rejected", reason=config.get("enforce_rejected_reason")))
    if config.get("breaker_open"):
        found.append(item("breaker_open"))
    if config.get("lift_pending"):
        found.append(item("lift_pending"))
    if config.get("behind_cdn"):
        found.append(item("behind_cdn"))
    first_seen = view["first_seen"]
    if view["reported_mode"] == "observe" and first_seen and now - first_seen >= WATCH_DAYS * DAY_SECONDS:
        found.append(item("watch_ready"))
    return found


def _count_events(db: Session, since: float, actions: tuple[str, ...]) -> int:
    return (
        db.query(func.count(SecurityEvent.id))
        .filter(
            SecurityEvent.ts >= since,
            SecurityEvent.simulated.is_(False),
            SecurityEvent.ok.is_(True),
            SecurityEvent.action.in_(actions),
        )
        .scalar()
    )


@router.get("/overview")
def overview(db: Session = Depends(_db)):
    now = time.time()
    commands = pending_by_node(db)
    servers = [server_view(a, now, commands) for a in _live_agents(db)]
    online = [s for s in servers if s["status"] == "online"]
    blocks_now = active_blocks(db, now)
    real = [b for b in blocks_now if not b["simulated"]]
    anomalies = db.query(Anomaly).order_by(Anomaly.ts.desc(), Anomaly.id.desc()).limit(RECENT_LIMIT)
    recent = recent_events(db, RECENT_LIMIT) + [a.as_dict() for a in anomalies]
    recent.sort(key=lambda row: row["ts"], reverse=True)
    return {
        "server_time": now,
        "protection": {
            "total": len(servers),
            "blocking": sum(s["reported_mode"] == "enforce" for s in online),
            "watching": sum(s["reported_mode"] == "observe" for s in online),
            "off": sum(s["reported_mode"] == "off" for s in online),
            "offline": len(servers) - len(online),
        },
        "blocked_24h": _count_events(db, now - DAY_SECONDS, BLOCK_ACTIONS),
        "rate_limited_24h": _count_events(db, now - DAY_SECONDS, ("rate_limit",)),
        "active": {
            "blocked": sum(b["kind"] != "rate_limit" for b in real),
            "slowed": sum(b["kind"] == "rate_limit" for b in real),
            "simulated": len(blocks_now) - len(real),
        },
        "watch_items": sum(len(w["items"]) for w in _watching(db, now, commands)),
        "attention": [a for s in servers for a in _attention(s, now)],
        "recent": recent[:RECENT_LIMIT],
        "servers": servers,
    }


class CustomerRequest(BaseModel):
    ip: str = Field(max_length=45)


@router.post("/customers")
def mark_customer(body: CustomerRequest, db: Session = Depends(_db)):
    network = _network(body.ip)
    if network is None or network.network_address.is_unspecified:
        raise HTTPException(400, "invalid IP address")
    # An IPv6 block covers the whole /64, so allowing one host would leave the customer blockable through a neighbour.
    ip = str(network.network_address) if network.version == 4 else str(ipaddress.ip_address(body.ip))
    sent, full = [], []
    for agent in _live_agents(db):
        current = agent.allowlist or []
        if not _covered(network, current):
            if len(current) >= MAX_ALLOWLIST:
                full.append(agent.node_id)
            else:
                agent.allowlist = [*current, str(network)]
                db.commit()
                enqueue(db, agent.node_id, "allowlist", {"ips": agent.allowlist})
        enqueue(db, agent.node_id, "unblock", {"ip": ip})
        if agent.node_id not in full:
            sent.append(agent.node_id)
    return {"status": "sent", "entry": str(network), "sent": sent, "full": full}
