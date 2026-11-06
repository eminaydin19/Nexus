from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexus_agent.parsers import parse_ssh_line, parse_web_line  # noqa: E402
from nexus_agent.protect import Protector  # noqa: E402
from nexus_agent.rules import Decision, RuleConfig, RuleEngine  # noqa: E402

SYSTEMS = ("fail2ban", "rules", "model", "hybrid")


class SimClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Stamped:
    ts: float
    decision: Decision


def _parse(source: str, line: str, ts: float):
    return (parse_ssh_line if source == "ssh" else parse_web_line)(line, ts)


def _fail2ban(lines, maxretry: int, findtime: float, bantime: float) -> List[Stamped]:
    hits = {}  # type: Dict[str, List[float]]
    banned_until = {}  # type: Dict[str, float]
    out = []
    for ts, source, line in lines:
        event = _parse(source, line, ts) if source == "ssh" else None
        if event is None or event.kind != "ssh_fail" or banned_until.get(event.ip, 0) > ts:
            continue
        recent = [t for t in hits.get(event.ip, []) if ts - t < findtime] + [ts]
        hits[event.ip] = recent
        if len(recent) >= maxretry:
            banned_until[event.ip] = ts + bantime
            hits[event.ip] = []
            out.append(Stamped(ts, Decision("fail2ban", event.ip, "block_port", (22,), int(bantime), "")))
    return out


def replay(lines: Iterable[Tuple[float, str, str]], system: str, models: Optional[dict] = None, maxretry: int = 5,
           findtime: float = 600.0, bantime: float = 600.0, allowlist=()) -> List[Stamped]:
    if system == "fail2ban":
        return _fail2ban(lines, maxretry, findtime, bantime)
    if system not in SYSTEMS:
        raise ValueError("unknown system: %s" % system)
    clock = SimClock()
    protector = Protector(allowlist=allowlist, clock=clock)
    engine = RuleEngine(RuleConfig(anomaly_block=1), protector, clock, models if system == "hybrid" else None)
    out = []
    flagged = set()
    for ts, source, line in lines:
        clock.now = ts
        event = _parse(source, line, ts)
        if event is None:
            continue
        decisions = engine.feed(event)
        if system != "model":
            out += [Stamped(ts, d) for d in decisions]
            continue
        channel = "ssh" if event.kind.startswith("ssh") else "web"
        if event.kind == "ssh_ok" or (channel, event.ip) not in engine._behavior._ips or (channel, event.ip) in flagged:
            continue
        model = models[channel]
        if model.score(engine._behavior.features(channel, event.ip)) >= model.threshold and not protector.reason(event.ip):
            flagged.add((channel, event.ip))
            out.append(Stamped(ts, Decision("model_only_" + channel, event.ip, "block_port", (), 900, "")))
    return out


def blocked(stamped: Iterable[Stamped]) -> Dict[str, float]:
    first = {}  # type: Dict[str, float]
    for item in stamped:
        if item.decision.action != "alert":
            first.setdefault(item.decision.ip, item.ts)
    return first
