import logging
import time

import httpx

log = logging.getLogger(__name__)


class SlackNotifier:
    def __init__(self, webhook_url: str, cooldown_seconds: int):
        self.webhook_url = webhook_url
        self.cooldown = cooldown_seconds
        self._last_sent: dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    async def notify(self, anomaly: dict) -> bool:
        if not self.enabled:
            return False
        node = anomaly["node"]
        now = time.monotonic()
        if now - self._last_sent.get(node, float("-inf")) < self.cooldown:
            return False
        self._last_sent[node] = now
        scores = anomaly["scores"]
        text = (
            f":rotating_light: *{anomaly['severity'].upper()}* anomaly on `{node}`\n"
            f"Score: *{scores['ensemble']:.2f}* | Main driver: *{anomaly['culprit']}*\n"
            f"CPU {anomaly['cpu_pct']:.1f}% | Memory {anomaly['memory_pct']:.1f}% | "
            f"Net {anomaly['net_kbps']:.1f} KB/s | Latency {anomaly['latency_ms']:.1f} ms"
        )
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(self.webhook_url, json={"text": text})
                response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            log.error("slack alert failed: %s", exc)
            return False
