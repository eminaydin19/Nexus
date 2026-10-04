from dataclasses import dataclass

import numpy as np

FEATURES = ("cpu_pct", "memory_pct", "net_kbps", "latency_ms")
FEATURE_SHORT = ("cpu", "memory", "network", "latency")
N_FEATURES = len(FEATURES)


@dataclass(frozen=True)
class NodeSnapshot:
    node_id: str
    timestamp: float
    cpu_pct: float
    memory_pct: float
    net_kbps: float
    latency_ms: float

    def vector(self) -> np.ndarray:
        return np.array(
            [self.cpu_pct, self.memory_pct, self.net_kbps, self.latency_ms],
            dtype=np.float64,
        )
