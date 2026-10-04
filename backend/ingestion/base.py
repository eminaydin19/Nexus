from typing import Protocol

from backend.schema import NodeSnapshot


class Source(Protocol):
    name: str
    interval: float

    async def poll(self) -> list[NodeSnapshot]: ...
