"""Minimal Prometheus text exposition (no external dependency)."""

import threading
from collections import defaultdict

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class Counters:
    """Thread-safe process-wide counters, optionally labelled."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, dict[tuple, float]] = defaultdict(dict)

    def inc(self, name: str, amount: float = 1.0, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            self._values[name][key] = self._values[name].get(key, 0.0) + amount

    def snapshot(self) -> dict[str, dict[tuple, float]]:
        with self._lock:
            return {name: dict(series) for name, series in self._values.items()}

    def reset(self) -> None:
        with self._lock:
            self._values.clear()


counters = Counters()


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _line(name: str, value: float, labels: dict[str, object] | tuple | None = None) -> str:
    pairs = dict(labels) if labels else {}
    label_text = ",".join(f'{k}="{_escape(v)}"' for k, v in pairs.items())
    return f"{name}{{{label_text}}} {value}" if label_text else f"{name} {value}"


def render(pipeline, defender) -> str:
    out: list[str] = []

    def family(name: str, kind: str, help_text: str, samples: list[tuple[dict, float]]) -> None:
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        out.extend(_line(name, value, labels) for labels, value in samples)

    nodes = list(pipeline.latest.values())
    family("nexus_nodes", "gauge", "Nodes currently known to Nexus.", [({}, len(nodes))])
    family("nexus_model_ready", "gauge", "1 when a trained model is loaded.", [({}, 1 if pipeline.ensemble.ready else 0)])
    family("nexus_ws_clients", "gauge", "Connected dashboard websocket clients.", [({}, len(pipeline.clients))])

    for metric, help_text in (
        ("cpu_pct", "Latest CPU utilisation percent."),
        ("memory_pct", "Latest memory utilisation percent."),
        ("net_kbps", "Latest network throughput in KB/s."),
        ("latency_ms", "Latest latency in milliseconds."),
    ):
        family(f"nexus_node_{metric}", "gauge", help_text, [({"node": n["node"]}, n[metric]) for n in nodes])

    family(
        "nexus_node_score",
        "gauge",
        "Latest ensemble anomaly score per node.",
        [({"node": n["node"]}, n["scores"]["ensemble"]) for n in nodes if n.get("scores")],
    )
    family(
        "nexus_node_anomalous",
        "gauge",
        "1 when the node is currently flagged anomalous.",
        [({"node": n["node"]}, 1 if n["status"] == "anomaly" else 0) for n in nodes],
    )

    status = defender.status() if defender else {}
    family("nexus_safe_mode", "gauge", "1 while Safe Mode is active.", [({}, 1 if status.get("safe_mode") else 0)])
    family("nexus_blocked_ips", "gauge", "IP addresses currently blocked.", [({}, len(status.get("blocked", [])))])

    snap = counters.snapshot()
    for name, help_text in (
        ("nexus_ingest_total", "Telemetry samples accepted via /api/ingest."),
        ("nexus_anomalies_total", "Anomalies recorded, by severity."),
        ("nexus_rate_limited_total", "Requests rejected by the rate limiter."),
        ("nexus_auth_failures_total", "Rejected ingest requests (bad or missing API key)."),
        ("nexus_defense_actions_total", "Defense actions taken, by action and mode."),
    ):
        series = snap.get(name, {})
        family(name, "counter", help_text, [(dict(k), v) for k, v in series.items()] or [({}, 0)])

    return "\n".join(out) + "\n"
