from backend.config import Settings
from backend.ingestion.base import Source


def build_source(settings: Settings) -> Source:
    if settings.ingestion_source == "cloudwatch":
        from backend.ingestion.cloudwatch import CloudWatchSource

        return CloudWatchSource(
            region=settings.aws_region,
            instance_ids=settings.instance_ids,
            period=settings.cloudwatch_period_seconds,
            access_key=settings.aws_access_key_id,
            secret_key=settings.aws_secret_access_key,
            memory_namespace=settings.cloudwatch_memory_namespace,
            memory_metric=settings.cloudwatch_memory_metric,
            latency_namespace=settings.cloudwatch_latency_namespace,
            latency_metric=settings.cloudwatch_latency_metric,
        )

    if settings.ingestion_source == "webhook":
        from backend.ingestion.webhook import WebhookSource
        return WebhookSource(interval=settings.cloudwatch_period_seconds)
