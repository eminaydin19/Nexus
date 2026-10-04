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
    anomaly_threshold: float = 0.0
    critical_score: float = 0.85

    slack_webhook_url: str = ""
    alert_cooldown_seconds: int = 900

    retention_days: int = 30

    dashboard_user: str = ""
    dashboard_password: str = ""

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
