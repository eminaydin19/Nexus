import time
from typing import Literal

from sqlalchemy import update
from sqlalchemy.orm import Session

from backend.db import AgentCommand

CommandType = Literal["unblock", "allowlist", "mode"]
_TYPES = {"unblock", "allowlist", "mode"}


def enqueue(db: Session, node_id: str, type: CommandType, payload: dict, commit: bool = True) -> int:
    if type not in _TYPES:
        raise ValueError(f"unsupported command type: {type}")
    if type == "mode":
        # A server coming back from offline must apply only the latest decision, not replay every change of mind.
        db.query(AgentCommand).filter(
            AgentCommand.node_id == node_id, AgentCommand.type == "mode", AgentCommand.acked_at.is_(None)
        ).delete(synchronize_session=False)
    row = AgentCommand(node_id=node_id, type=type, payload=payload, created_at=time.time())
    db.add(row)
    if commit:
        db.commit()
    else:
        db.flush()
    return row.id


def pending(db: Session, node_id: str) -> list[dict]:
    rows = (
        db.query(AgentCommand)
        .filter(AgentCommand.node_id == node_id, AgentCommand.acked_at.is_(None))
        .order_by(AgentCommand.id)
    )
    return [{"id": r.id, "type": r.type, "payload": r.payload} for r in rows]


def ack(db: Session, node_id: str, ids: list[int]) -> None:
    if not ids:
        return
    db.execute(
        update(AgentCommand)
        .where(AgentCommand.node_id == node_id, AgentCommand.id.in_(ids), AgentCommand.acked_at.is_(None))
        .values(acked_at=time.time())
    )
    db.commit()
