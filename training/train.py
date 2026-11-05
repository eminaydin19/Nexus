import argparse
import csv
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import torch

from backend.config import settings
from backend.models.ensemble import BUNDLE_FORMAT, Ensemble
from backend.models.features import FeatureScaler
from backend.models.isolation_forest import IsolationForestModel
from backend.models.lstm_autoencoder import LSTMAutoEncoder
from backend.models.transformer_autoencoder import TransformerAutoEncoder
from backend.models.vae import VAE
from backend.schema import FEATURES, N_FEATURES

log = logging.getLogger("train")

MIN_NODE_ROWS = 50

NodeData = dict[str, tuple[np.ndarray, np.ndarray]]


class NotEnoughDataError(Exception):
    pass


def load_db() -> NodeData:
    from backend.db import Metric, SessionLocal, init_db

    init_db()
    rows: dict[str, list[list[float]]] = {}
    with SessionLocal() as session:
        query = (
            session.query(Metric)
            .filter(Metric.is_anomaly.is_(False))
            .order_by(Metric.node_id, Metric.ts)
            .yield_per(5000)
        )
        for m in query:
            rows.setdefault(m.node_id, []).append([m.ts, m.cpu_pct, m.memory_pct, m.net_kbps, m.latency_ms])
    return {node: _split_columns(np.array(values)) for node, values in rows.items()}


def load_csv(path: Path) -> NodeData:
    rows: dict[str, list[list[float]]] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"node_id", "timestamp", *FEATURES}
        if not required.issubset(reader.fieldnames or []):
            raise SystemExit(f"CSV must contain columns: {', '.join(sorted(required))}")
        for record in reader:
            if record.get("label", "0").strip() in {"1", "true", "True"}:
                continue
            rows.setdefault(record["node_id"], []).append(
                [float(record["timestamp"]), *(float(record[f]) for f in FEATURES)]
            )
    return {node: _split_columns(np.array(values)) for node, values in rows.items()}





def _split_columns(array: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    order = np.argsort(array[:, 0], kind="stable")
    array = array[order]
    return array[:, 0], array[:, 1:]


def segments(ts: np.ndarray, x: np.ndarray) -> list[np.ndarray]:
    if len(ts) < 2:
        return [x] if len(x) else []
    steps = np.diff(ts)
    limit = max(3.0 * float(np.median(steps)), 1e-6)
    cuts = np.flatnonzero(steps > limit) + 1
    return [part for part in np.split(x, cuts) if len(part)]


def windows_from(parts: list[np.ndarray], window: int) -> np.ndarray:
    out = [
        np.ascontiguousarray(np.lib.stride_tricks.sliding_window_view(p, window, axis=0).transpose(0, 2, 1))
        for p in parts
        if len(p) >= window
    ]
    if not out:
        return np.empty((0, window, N_FEATURES), dtype=np.float32)
    return np.concatenate(out).astype(np.float32)


def cap(array: np.ndarray, limit: int, rng: np.random.Generator) -> np.ndarray:
    if len(array) <= limit:
        return array
    return array[np.sort(rng.choice(len(array), limit, replace=False))]


def ordinary_mask(
    values: np.ndarray, older: np.ndarray | None = None, spread: float = 6.0, frequent: float = 98.0
) -> np.ndarray:
    median = np.median(values)
    mad = np.median(np.abs(values - median))
    limit = median + spread * 1.4826 * max(mad, 1e-9)
    # A state seen in over 2% of older history recurs, whatever its distance: a cron job takes 13% of a batch server's
    # time, and leaving it out of calibration makes the job alarm every time it runs. Only older history can vouch for
    # a state, because an incident in the newest rows can be a large share of them.
    return values <= max(limit, np.percentile(values if older is None else older, frequent))


def train(data: NodeData, window: int, epochs: int, min_rows: int, seed: int, source_name: str) -> dict:
    started = time.time()
    rng = np.random.default_rng(seed)

    total_rows = sum(len(x) for _, x in data.values())
    if total_rows < min_rows:
        raise NotEnoughDataError(
            f"Not enough data: {total_rows} rows, need at least {min_rows}. Let the collector run longer."
        )

    train_parts: dict[str, list[np.ndarray]] = {}
    val_parts: dict[str, list[np.ndarray]] = {}
    holdout_parts: dict[str, list[np.ndarray]] = {}
    for node, (ts, x) in data.items():
        cut, holdout_cut = int(len(x) * 0.8), int(len(x) * 0.9)
        train_parts[node] = segments(ts[:cut], x[:cut])
        val_parts[node] = segments(ts[cut:holdout_cut], x[cut:holdout_cut])
        holdout_parts[node] = segments(ts[holdout_cut:], x[holdout_cut:])

    default_scaler = FeatureScaler.fit(np.concatenate([p for parts in train_parts.values() for p in parts]))
    scalers = {
        node: FeatureScaler.fit(np.concatenate(parts))
        for node, parts in train_parts.items()
        if sum(len(p) for p in parts) >= MIN_NODE_ROWS
    }
    def scaled_parts(parts_by_node: dict[str, list[np.ndarray]]) -> dict[str, list[np.ndarray]]:
        return {
            node: [scalers.get(node, default_scaler).transform(p) for p in parts] for node, parts in parts_by_node.items()
        }

    train_by_node, val_by_node, holdout_by_node = map(scaled_parts, (train_parts, val_parts, holdout_parts))
    train_scaled_parts = [p for parts in train_by_node.values() for p in parts]

    # At a 5 second interval history reaches hundreds of thousands of rows, and training repeats every day.
    train_scaled = cap(np.concatenate(train_scaled_parts), 40000, rng)
    train_windows = cap(windows_from(train_scaled_parts, window), 40000, rng)
    if len(train_windows) < 200:
        raise NotEnoughDataError(f"Not enough contiguous history: {len(train_windows)} windows of {window} steps, need 200.")

    log.info("training on %d rows, %d windows from %d nodes", len(train_scaled), len(train_windows), len(data))

    iforest = IsolationForestModel.fit(train_scaled, seed=seed)
    vae = VAE()
    vae_loss = vae.fit(train_scaled, epochs=epochs, seed=seed)
    lstm = LSTMAutoEncoder()
    lstm_loss = lstm.fit(train_windows, epochs=epochs, seed=seed)
    transformer = TransformerAutoEncoder()
    transformer_loss = transformer.fit(train_windows, epochs=epochs, seed=seed)
    log.info("final loss: vae=%.4f lstm=%.4f transformer=%.4f", vae_loss, lstm_loss, transformer_loss)

    def raw_errors(windows: np.ndarray) -> dict[str, np.ndarray]:
        last = windows[:, -1, :]
        return {
            "iforest": iforest.error(last),
            "lstm": lstm.error(windows),
            "transformer": transformer.error(windows),
            "vae": vae.error(last),
        }

    # The newest history can hold an incident. Calibrating on it would make the next attack look normal, so calibrate
    # on train and validation together and leave out windows no model finds ordinary. Each node keeps its own share:
    # what is ordinary for a batch server is not ordinary for a web server.
    node_calibration: dict[str, np.ndarray] = {}
    limit = max(1000, 20000 // len(data))
    for node in data:
        older = cap(windows_from(train_by_node[node], window), limit // 2, rng)
        node_windows = np.concatenate([cap(windows_from(val_by_node[node], window), limit // 2, rng), older])
        if not len(node_windows):
            continue
        all_errors = raw_errors(node_windows)
        ordinary = np.logical_and.reduce([
            ordinary_mask(values, values[-len(older):] if len(older) else None) for values in all_errors.values()
        ])
        node_calibration[node] = node_windows[ordinary]
    val_windows = np.concatenate(list(node_calibration.values()))
    errors = raw_errors(val_windows)
    calibration = {}
    for key, values in errors.items():
        lo = float(np.median(values))
        hi = float(np.percentile(values, 99))
        calibration[key] = [lo, max(hi, lo + 1e-9)]

    bundle = {
        "format": BUNDLE_FORMAT,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window": window,
        "scalers": {node: sc.to_dict() for node, sc in scalers.items()},
        "default_scaler": default_scaler.to_dict(),
        "iforest": iforest.forest,
        "lstm": lstm.to_state(),
        "transformer": transformer.to_state(),
        "vae": vae.to_state(),
        "calibration": calibration,
        "threshold": 0.5,
    }
    ensemble = Ensemble(
        {
            "iforest": settings.weight_isolation_forest,
            "lstm": settings.weight_lstm_ae,
            "transformer": settings.weight_transformer,
            "vae": settings.weight_vae,
        }
    )
    ensemble.install_bundle(bundle)

    def combined(windows: np.ndarray) -> np.ndarray:
        return ensemble.combine(ensemble.score_arrays(windows))

    normal = combined(val_windows)
    threshold = float(max(0.5, np.percentile(normal, 99.5)))
    bundle["threshold"] = threshold
    thresholds = {
        node: float(max(0.5, np.percentile(combined(windows), 99.5)))
        for node, windows in node_calibration.items() if len(windows) >= MIN_NODE_ROWS
    }
    bundle["thresholds"] = thresholds

    # Measured on the newest tenth of history, which neither training nor any threshold saw. An incident there counts
    # against the rate: the number errs toward looking worse, never better.
    alarms, seen = 0, 0
    for node, parts in holdout_by_node.items():
        node_windows = cap(windows_from(parts, window), 10000, rng)
        if len(node_windows):
            alarms += int(np.sum(combined(node_windows) >= thresholds.get(node, threshold)))
            seen += len(node_windows)
    eval_on = "holdout" if seen >= 50 else "calibration"
    false_positive_rate = alarms / seen if seen >= 50 else float(np.mean(normal >= threshold))

    recalls = {}
    for sigma in (4, 8):
        shifted = val_windows.copy()
        features = rng.integers(0, N_FEATURES, len(shifted))
        shifted[np.arange(len(shifted)), -1, features] += sigma
        recalls[f"recall_{sigma}sigma"] = float(np.mean(ensemble.combine(ensemble.score_arrays(shifted)) >= threshold))

    bundle["report"] = {
        "source": source_name,
        "rows": int(total_rows),
        "nodes": len(data),
        "train_windows": len(train_windows),
        "eval_windows": len(val_windows),
        "eval_on": eval_on,
        "epochs": epochs,
        "false_positive_rate": false_positive_rate,
        **recalls,
        "seconds": round(time.time() - started, 1),
    }
    return bundle


def save(bundle: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    joblib.dump(bundle, tmp)
    os.replace(tmp, path)


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m training.train")
    parser.add_argument("--source", choices=["db", "csv"], default="db")
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--window", type=int, default=12)
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--min-rows", type=int, default=500)

    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=settings.bundle_path)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    torch.set_num_threads(max(1, os.cpu_count() or 1))

    if args.source == "csv":
        if not args.csv:
            parser.error("--csv is required with --source csv")
        data = load_csv(args.csv)
    else:
        data = load_db()

    if not data:
        sys.exit("No data found.")

    try:
        bundle = train(data, args.window, args.epochs, args.min_rows, args.seed, args.source)
    except NotEnoughDataError as e:
        raise SystemExit(str(e))
    save(bundle, args.output)

    report = bundle["report"]
    log.info("saved %s", args.output)
    log.info("threshold=%.3f  false_positive_rate=%.4f", bundle["threshold"], report["false_positive_rate"])
    log.info("synthetic spike recall: 4sigma=%.3f 8sigma=%.3f", report["recall_4sigma"], report["recall_8sigma"])


if __name__ == "__main__":
    main()
