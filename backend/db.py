from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    Index,
    Integer,
    String,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from backend.config import settings

Path(settings.data_dir).mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False} if settings.db_url.startswith("sqlite") else {},
    pool_pre_ping=True,
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, _record):
    if settings.db_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Metric(Base):
    __tablename__ = "metrics"
    __table_args__ = (Index("ix_metrics_node_ts", "node_id", "ts"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(String(128))
    ts: Mapped[float] = mapped_column(Float, index=True)
    cpu_pct: Mapped[float] = mapped_column(Float)
    memory_pct: Mapped[float] = mapped_column(Float)
    net_kbps: Mapped[float] = mapped_column(Float)
    latency_ms: Mapped[float] = mapped_column(Float)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)


class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(String(128), index=True)
    ts: Mapped[float] = mapped_column(Float, index=True)
    culprit: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    cpu_pct: Mapped[float] = mapped_column(Float)
    memory_pct: Mapped[float] = mapped_column(Float)
    net_kbps: Mapped[float] = mapped_column(Float)
    latency_ms: Mapped[float] = mapped_column(Float)
    ensemble_score: Mapped[float] = mapped_column(Float)
    if_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    lstm_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    vae_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    transformer_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    flags: Mapped[list] = mapped_column(JSON, default=list)
    contributions: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "node": self.node_id,
            "ts": self.ts,
            "detected_at": datetime.fromtimestamp(self.ts, tz=timezone.utc).isoformat(),
            "culprit": self.culprit,
            "severity": self.severity,
            "cpu_pct": self.cpu_pct,
            "memory_pct": self.memory_pct,
            "net_kbps": self.net_kbps,
            "latency_ms": self.latency_ms,
            "scores": {
                "ensemble": self.ensemble_score,
                "iforest": self.if_score,
                "lstm": self.lstm_score,
                "vae": self.vae_score,
                "transformer": self.transformer_score,
            },
            "flags": self.flags or [],
            "contributions": self.contributions or {},
        }


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (Index("ix_security_events_node_ts", "node_id", "ts"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(String(128))
    ts: Mapped[float] = mapped_column(Float, index=True)
    rule: Mapped[str] = mapped_column(String(64), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    action: Mapped[str] = mapped_column(String(16))
    ports: Mapped[list] = mapped_column(JSON, default=list)
    ttl: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[str] = mapped_column(String(500), default="")
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "node_id": self.node_id,
            "ts": self.ts,
            "rule": self.rule,
            "ip": self.ip,
            "action": self.action,
            "ports": self.ports or [],
            "ttl": self.ttl,
            "evidence": self.evidence,
            "simulated": self.simulated,
            "ok": self.ok,
        }


class ActiveBlock(Base):
    __tablename__ = "active_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(String(128), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    rule: Mapped[str] = mapped_column(String(64))
    ports: Mapped[list] = mapped_column(JSON, default=list)
    until: Mapped[float] = mapped_column(Float)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "ip": self.ip,
            "rule": self.rule,
            "ports": self.ports or [],
            "until": self.until,
            "simulated": self.simulated,
        }


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(String(128), index=True)
    type: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[float] = mapped_column(Float)
    acked_at: Mapped[float | None] = mapped_column(Float, nullable=True)


class Agent(Base):
    __tablename__ = "agents"

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[float] = mapped_column(Float)
    first_seen: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_seen: Mapped[float | None] = mapped_column(Float, nullable=True)
    revoked_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    mode: Mapped[str] = mapped_column(String(16), default="observe")
    max_mode: Mapped[str] = mapped_column(String(16), default="observe")
    version: Mapped[str] = mapped_column(String(32), default="")
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    allowlist: Mapped[list] = mapped_column(JSON, default=list)

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "created_at": self.created_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "revoked_at": self.revoked_at,
            "mode": self.mode,
            "max_mode": self.max_mode,
            "version": self.version,
            "capabilities": self.capabilities,
            "config": self.config,
            "allowlist": self.allowlist,
        }


class EnrollToken(Base):
    __tablename__ = "enroll_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[float] = mapped_column(Float)
    expires_at: Mapped[float] = mapped_column(Float)
    used_at: Mapped[float | None] = mapped_column(Float, nullable=True)


# Columns added after the first release: (table, column, DDL type).
_ADDITIVE_COLUMNS = [("anomalies", "contributions", "JSON"), ("anomalies", "transformer_score", "FLOAT")]


def _migrate() -> None:
    inspector = inspect(engine)
    for table, column, ddl in _ADDITIVE_COLUMNS:
        if table in inspector.get_table_names() and column not in {c["name"] for c in inspector.get_columns(table)}:
            with engine.begin() as conn:
                conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}'))


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _migrate()
