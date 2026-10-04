import asyncio
from backend.schema import NodeSnapshot

class WebhookSource:
    name = "webhook"

    def __init__(self, interval: float = 60.0):
        self.interval = interval

    async def poll(self) -> list[NodeSnapshot]:
        # This source is passive. The actual ingestion happens via /api/ingest POST.
        # We just sleep to prevent the pipeline poll loop from spinning fast.
        await asyncio.sleep(self.interval)
        return []
