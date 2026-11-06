from __future__ import annotations

import json
import logging
import math
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

log = logging.getLogger("nexus_agent.anomaly")

WINDOW = 3600.0
MAX_PATHS = 256
MAX_USERS = 64
MAX_PORTS = 64
MODEL_FILE = Path(__file__).parent / "data" / "anomaly_model.json"
_STATIC = (".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".map")
_EULER = 0.5772156649015329

WEB_FEATURES = (
    "requests_per_min", "log_requests", "distinct_path_ratio", "ok_ratio", "err4xx_ratio", "err5xx_ratio", "static_ratio",
    "no_user_agent_ratio", "interval_cv", "browser_ratio", "suspicious_ratio",
)
SSH_FEATURES = ("attempts_per_min", "log_attempts", "distinct_users", "invalid_ratio", "interval_cv")
FEATURES = {"web": WEB_FEATURES, "ssh": SSH_FEATURES}


def average_path(n: float) -> float:
    if n <= 1:
        return 0.0
    if n <= 2:
        return 1.0
    return 2.0 * (math.log(n - 1.0) + _EULER) - 2.0 * (n - 1.0) / n


class Forest:
    def __init__(self, spec: dict):
        self.threshold = float(spec["threshold"])
        self.features = tuple(spec["features"])
        self._trees = [(t["f"], t["t"], t["l"], t["r"], t["n"]) for t in spec["trees"]]
        if not self._trees:
            raise ValueError("forest has no trees")
        self._norm = average_path(float(spec["max_samples"])) * len(self._trees)

    def score(self, row: Sequence[float]) -> float:
        total = 0.0
        for feature, threshold, left, right, samples in self._trees:
            node, depth = 0, 0
            while left[node] >= 0:
                node = left[node] if row[feature[node]] <= threshold[node] else right[node]
                depth += 1
            total += depth + average_path(samples[node])
        return 2.0 ** (-total / self._norm)


def load_models(path: Optional[Path] = None) -> Dict[str, Forest]:
    try:
        raw = json.loads(Path(path or MODEL_FILE).read_text())
        models = {channel: Forest(raw[channel]) for channel in FEATURES}
        for channel, model in models.items():
            if model.features != FEATURES[channel]:
                raise ValueError("%s model has other features" % channel)
        return models
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        log.warning("anomaly model unavailable, anomaly detection is off: %s", exc)
        return {}


class _Counts:
    __slots__ = ("start", "last", "n", "gap_n", "gap_mean", "gap_m2", "evidence", "ok", "err4", "err5", "static", "no_ua",
                 "browser", "invalid", "paths", "users", "ports")

    def __init__(self, now: float):
        self.start, self.last = now, None
        self.n = self.gap_n = self.evidence = self.ok = self.err4 = self.err5 = self.static = self.no_ua = self.browser = self.invalid = 0
        self.gap_mean = self.gap_m2 = 0.0
        self.paths, self.users, self.ports = set(), set(), set()  # type: set, set, set

    def tick(self, now: float) -> None:
        if self.last is not None:
            gap = max(now - self.last, 0.0)
            self.gap_n += 1
            delta = gap - self.gap_mean
            self.gap_mean += delta / self.gap_n
            self.gap_m2 += delta * (gap - self.gap_mean)
        self.last = now
        self.n += 1

    def cv(self) -> float:
        if self.gap_n < 2 or self.gap_mean <= 0:
            return 0.0
        return math.sqrt(self.gap_m2 / self.gap_n) / self.gap_mean

    def per_min(self, now: float) -> float:
        return self.n * 60.0 / max(now - self.start, 60.0)


class Behavior:

    def __init__(self, max_ips: int = 100000, clock: Callable[[], float] = time.time):
        self._max = max_ips
        self._clock = clock
        self._ips = OrderedDict()  # type: OrderedDict

    def _entry(self, channel: str, ip: str) -> _Counts:
        now = self._clock()
        key = (channel, ip)
        c = self._ips.get(key)
        if c is None or now - c.start >= WINDOW:
            c = self._ips[key] = _Counts(now)
        self._ips.move_to_end(key)
        while len(self._ips) > self._max:
            self._ips.popitem(last=False)
        return c

    def note_web(self, ip: str, path: str, status: int, user_agent: Optional[str], is_evidence: bool) -> None:
        c = self._entry("web", ip)
        c.tick(self._clock())
        c.evidence += bool(is_evidence)
        if len(c.paths) < MAX_PATHS:
            c.paths.add(path)
        c.ok += 200 <= status < 400
        c.err4 += 400 <= status < 500
        c.err5 += status >= 500
        c.static += path.lower().endswith(_STATIC)
        c.no_ua += not user_agent
        c.browser += bool(user_agent) and user_agent.startswith("Mozilla/5.0 (")

    def note_ssh(self, ip: str, user: Optional[str], invalid: bool, port: Optional[int], password_try: bool) -> None:
        c = self._entry("ssh", ip)
        if port is not None and port in c.ports and not password_try:
            return
        if port is not None and len(c.ports) < MAX_PORTS:
            c.ports.add(port)
        c.tick(self._clock())
        c.evidence += 1
        c.invalid += bool(invalid)
        if user is not None and len(c.users) < MAX_USERS:
            c.users.add(user)

    def evidence(self, channel: str, ip: str) -> int:
        c = self._ips.get((channel, ip))
        return c.evidence if c is not None else 0

    def features(self, channel: str, ip: str) -> List[float]:
        c = self._ips[(channel, ip)]
        now = self._clock()
        n = max(c.n, 1)
        if channel == "ssh":
            return [c.per_min(now), math.log1p(c.n), float(len(c.users)), c.invalid / n, c.cv()]
        return [c.per_min(now), math.log1p(c.n), len(c.paths) / n, c.ok / n, c.err4 / n, c.err5 / n, c.static / n,
                c.no_ua / n, c.cv(), c.browser / n, c.evidence / n]

    def forget(self, ip: str) -> None:
        for channel in FEATURES:
            self._ips.pop((channel, ip), None)
