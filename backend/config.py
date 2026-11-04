import re
from pathlib import Path
from typing import Literal

from pydantic import field_validator
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

    # Per-client request budget per minute (0 disables rate limiting).
    rate_limit_per_minute: int = 300
    # Honour X-Forwarded-For. Only enable behind a trusted reverse proxy (e.g. Caddy).
    trust_proxy_headers: bool = False
    # The address agents enroll with. Set by install.sh, never derived from a request.
    public_url: str = ""

    @field_validator("public_url")
    @classmethod
    def _origin_only(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        # This value lands inside a shell script that people pipe into sudo bash.
        if value and not re.fullmatch(r"https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:\d+)?", value):
            raise ValueError("PUBLIC_URL must look like https://host[:port]")
        return value

    def require_dashboard_credentials(self) -> None:
        if not (self.dashboard_user and self.dashboard_password):
            raise RuntimeError("DASHBOARD_USER and DASHBOARD_PASSWORD must be set")

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
    def instance_ids(self) -> list[str]:
        return [i.strip() for i in self.ec2_instance_ids.split(",") if i.strip()]


settings = Settings()
