from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    data_dir: str = "data"
    database_url: str = ""

    ingestion_source: Literal["cloudwatch", "webhook"] = "webhook"

    aws_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    ec2_instance_ids: str = ""
    cloudwatch_period_seconds: int = 300
    cloudwatch_memory_namespace: str = "CWAgent"
    cloudwatch_memory_metric: str = "mem_used_percent"
    cloudwatch_latency_namespace: str = "Nexus"
    cloudwatch_latency_metric: str = "RequestLatency"

    weight_isolation_forest: float = 0.25
    weight_lstm_ae: float = 0.45
    weight_vae: float = 0.30
    weight_transformer: float = 0.30
    anomaly_threshold: float = 0.0
    critical_score: float = 0.85

    slack_webhook_url: str = ""
    alert_cooldown_seconds: int = 900

    retention_days: int = 30

    dashboard_user: str = ""
    dashboard_password: str = ""

    # Shared secret agents must send in the X-API-Key header (or Bearer token) to /api/ingest.
    ingest_api_key: str = ""
    # Per-client request budget per minute (0 disables rate limiting).
    rate_limit_per_minute: int = 300
    # Honour X-Forwarded-For. Only enable behind a trusted reverse proxy (e.g. Caddy).
    trust_proxy_headers: bool = False

    # Active defense. "dry_run" only logs/records what it would do; "enforce" runs firewall commands.
    defense_mode: Literal["off", "dry_run", "enforce"] = "dry_run"
    defense_firewall: Literal["auto", "iptables", "nftables", "pfctl"] = "auto"
    defense_block_seconds: int = 300
    defense_safe_mode_seconds: int = 60
    # Comma separated IPs/CIDRs that must never be blocked.
    defense_allowlist: str = "127.0.0.1,::1"

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir)

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{self.data_path.resolve() / 'nexus.db'}"

    @property
    def bundle_path(self) -> Path:
        return self.data_path / "models" / "ensemble.joblib"

    @property
    def allowlist(self) -> list[str]:
        return [i.strip() for i in self.defense_allowlist.split(",") if i.strip()]

    @property
    def instance_ids(self) -> list[str]:
        return [i.strip() for i in self.ec2_instance_ids.split(",") if i.strip()]


settings = Settings()
