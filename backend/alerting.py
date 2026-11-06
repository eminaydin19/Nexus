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

    def _due(self, key: str) -> bool:
        now = time.monotonic()
        if now - self._last_sent.get(key, float("-inf")) < self.cooldown:
            return False
        self._last_sent[key] = now
        return True

    async def _post(self, text: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(self.webhook_url, json={"text": text})
                response.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            log.error("slack alert failed: %s", exc)
            return False

    async def notify(self, anomaly: dict) -> bool:
        node = anomaly["node"]
        if not self.enabled or not self._due(node):
            return False
        scores = anomaly["scores"]
        return await self._post(
            f":rotating_light: *{anomaly['severity'].upper()}* anomaly on `{node}`\n"
            f"Score: *{scores['ensemble']:.2f}* | Main driver: *{anomaly['culprit']}*\n"
            f"CPU {anomaly['cpu_pct']:.1f}% | Memory {anomaly['memory_pct']:.1f}% | "
            f"Net {anomaly['net_kbps']:.1f} KB/s | Latency {anomaly['latency_ms']:.1f} ms"
        )

    async def notify_event(self, event: dict) -> bool:
        if not self.enabled or not self._due(f"event:{event['node_id']}:{event['rule']}"):
            return False
        e = {k: _escape(str(v)) for k, v in event.items() if k != "ports"}
        ports = ",".join(_escape(str(p)) for p in event["ports"]) or "-"
        text = (
            f":rotating_light: *{e['rule']}* on `{e['node_id']}`\n"
            f"Action: *{e['action']}* | IP: `{e['ip']}` | Ports: {ports} | TTL: {e['ttl']}s\n"
            f"Evidence: {e['evidence']}"
        )
        return await self._post(text)


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
