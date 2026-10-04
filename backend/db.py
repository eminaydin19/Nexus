from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, create_engine, event
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
    flags: Mapped[list] = mapped_column(JSON, default=list)

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
            },
            "flags": self.flags or [],
        }


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
