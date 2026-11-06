import asyncio

from backend.schema import NodeSnapshot


class WebhookSource:
    name = "webhook"

    def __init__(self, interval: float = 60.0):
        self.interval = interval

    async def poll(self) -> list[NodeSnapshot]:
        await asyncio.sleep(self.interval)
        return []
