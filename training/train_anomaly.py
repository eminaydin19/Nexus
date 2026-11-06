"""Fit the per-IP Isolation Forests on legitimate behavior and export them for the agent. Needs scikit-learn.

python -m training.train_anomaly --output nexus_agent/data/anomaly_model.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexus_agent.anomaly import FEATURES, Forest  # noqa: E402
from nexus_agent.parsers import parse_ssh_line, parse_web_line  # noqa: E402
from nexus_agent.protect import Protector  # noqa: E402
from nexus_agent.rules import RuleConfig, RuleEngine, _ident  # noqa: E402
from scripts.replay import SimClock  # noqa: E402
from training.anomaly_sim import simulate  # noqa: E402

TRAIN_SEEDS = (1, 2, 3, 4, 5)
THRESHOLD_SEEDS = (6, 7)
TARGET_PRECISION = 0.99
MIN_EVIDENCE = RuleConfig().anomaly_min_evidence


def rows_by_address(records) -> dict:
    """channel -> address -> (label, feature rows after each of its events, evidence count at each)."""
    clock = SimClock()
    engine = RuleEngine(RuleConfig(), Protector(clock=clock), clock)
    out = {"web": {}, "ssh": {}}
    for ts, source, line, label, ip in records:
        clock.now = ts
        event = (parse_ssh_line if source == "ssh" else parse_web_line)(line, ts)
        if event is None or event.kind == "ssh_ok":
            continue
        engine.feed(event)
        ident = _ident(event.ip)
        if (source, ident) in engine._behavior._ips:
            entry = out[source].setdefault(ident, (label, [], []))
            entry[1].append(engine._behavior.features(source, ident))
            entry[2].append(engine._behavior.evidence(source, ident))
    return out


def export_forest(forest: IsolationForest, features, threshold: float) -> dict:
    trees = []
    for est in forest.estimators_:
        t = est.tree_
        trees.append({
            "f": t.feature.tolist(),
            "t": [round(v, 6) for v in t.threshold.tolist()],
            "l": t.children_left.tolist(),
            "r": t.children_right.tolist(),
            "n": t.n_node_samples.tolist(),
        })
    return {"threshold": threshold, "features": list(features), "max_samples": int(forest.max_samples_), "trees": trees}


def fit(rows: np.ndarray, seed: int) -> IsolationForest:
    return IsolationForest(n_estimators=60, max_samples=min(256, len(rows)), random_state=seed, n_jobs=1).fit(rows)


def pick_threshold(scored: list, target: float = TARGET_PRECISION) -> float:
    """The lowest score that keeps precision at the target, over (score, is_attack) per address that passed the gate."""
    if not any(not attack for _, attack in scored):
        raise ValueError("no legitimate address reached the gate, so a threshold cannot be set")
    ordered = sorted(scored, reverse=True)
    best, attacks = None, 0
    for i, (score, attack) in enumerate(ordered, 1):
        attacks += attack
        if attacks / i >= target:
            best = score
    if best is None:
        raise ValueError("no threshold reaches the target precision")
    return float(best)


def legit_rows(by_address: dict, channel: str, legit_label) -> np.ndarray:
    """Only rows past the gate, the one place the model is ever asked. The question it answers is "does this address with
    evidence behave like a customer who also had evidence", and comparing against ordinary browsing missed every scanner."""
    rows = [row for label, rows, evidence in by_address[channel].values() if legit_label(label)
            for row, count in zip(rows, evidence) if count >= MIN_EVIDENCE]
    return np.array(rows, dtype=float)


def train(train_records, threshold_records, seed: int = 42) -> dict:
    by_address = rows_by_address(train_records)
    calibration = rows_by_address(threshold_records)
    out = {}
    for channel, features in FEATURES.items():
        forest = fit(legit_rows(by_address, channel, lambda label: label.startswith("customer")), seed)
        scorer = Forest(export_forest(forest, features, 0.0))
        scored = []
        for label, rows, evidence in calibration[channel].values():
            gated = [row for row, count in zip(rows, evidence) if count >= MIN_EVIDENCE]
            if gated:
                scored.append((max(scorer.score(row) for row in gated), label.startswith("attack")))
        out[channel] = export_forest(forest, features, pick_threshold(scored))
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    train_records = [r for seed in TRAIN_SEEDS for r in simulate(seed)]
    threshold_records = [r for seed in THRESHOLD_SEEDS for r in simulate(seed)]
    model = train(train_records, threshold_records)
    args.output.write_text(json.dumps(model, separators=(",", ":")))
    print({channel: model[channel]["threshold"] for channel in model}, args.output.stat().st_size)


if __name__ == "__main__":
    main()
