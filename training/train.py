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

NodeData = dict[str, tuple[np.ndarray, np.ndarray]]


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


def train(data: NodeData, window: int, epochs: int, min_rows: int, seed: int, source_name: str) -> dict:
    started = time.time()
    rng = np.random.default_rng(seed)

    total_rows = sum(len(x) for _, x in data.values())
    if total_rows < min_rows:
        raise SystemExit(
            f"Not enough data: {total_rows} rows, need at least {min_rows}. Let the collector run longer."
        )

    train_parts: list[np.ndarray] = []
    val_parts: list[np.ndarray] = []
    for ts, x in data.values():
        cut = int(len(x) * 0.8)
        train_parts.extend(segments(ts[:cut], x[:cut]))
        val_parts.extend(segments(ts[cut:], x[cut:]))

    train_rows = np.concatenate(train_parts)
    scaler = FeatureScaler.fit(train_rows)
    train_scaled_parts = [scaler.transform(p) for p in train_parts]
    val_scaled_parts = [scaler.transform(p) for p in val_parts]

    train_scaled = np.concatenate(train_scaled_parts)
    train_windows = cap(windows_from(train_scaled_parts, window), 40000, rng)
    if len(train_windows) < 200:
        raise SystemExit(f"Not enough contiguous history: {len(train_windows)} windows of {window} steps, need 200.")

    log.info("training on %d rows, %d windows from %d nodes", len(train_scaled), len(train_windows), len(data))

    iforest = IsolationForestModel.fit(train_scaled, seed=seed)
    vae = VAE()
    vae_loss = vae.fit(train_scaled, epochs=epochs, seed=seed)
    lstm = LSTMAutoEncoder()
    lstm_loss = lstm.fit(train_windows, epochs=epochs, seed=seed)
    transformer = TransformerAutoEncoder()
    transformer_loss = transformer.fit(train_windows, epochs=epochs, seed=seed)
    log.info("final loss: vae=%.4f lstm=%.4f transformer=%.4f", vae_loss, lstm_loss, transformer_loss)

    val_windows = windows_from(val_scaled_parts, window)
    eval_on = "validation"
    if len(val_windows) < 50:
        log.warning("validation set too small (%d windows), calibrating on training data", len(val_windows))
        val_windows = cap(train_windows, 5000, rng)
        eval_on = "train"
    val_windows = cap(val_windows, 10000, rng)

    last = val_windows[:, -1, :]
    errors = {
        "iforest": iforest.error(last),
        "lstm": lstm.error(val_windows),
        "transformer": transformer.error(val_windows),
        "vae": vae.error(last),
    }
    calibration = {}
    for key, values in errors.items():
        lo = float(np.median(values))
        hi = float(np.percentile(values, 99))
        calibration[key] = [lo, max(hi, lo + 1e-9)]

    bundle = {
        "format": BUNDLE_FORMAT,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window": window,
        "scaler": scaler.to_dict(),
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

    normal = ensemble.combine(ensemble.score_arrays(val_windows))
    threshold = float(max(0.5, np.percentile(normal, 99.5)))
    bundle["threshold"] = threshold

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
        "train_windows": int(len(train_windows)),
        "eval_windows": int(len(val_windows)),
        "eval_on": eval_on,
        "epochs": epochs,
        "false_positive_rate": float(np.mean(normal >= threshold)),
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

    bundle = train(data, args.window, args.epochs, args.min_rows, args.seed, args.source)
    save(bundle, args.output)

    report = bundle["report"]
    log.info("saved %s", args.output)
    log.info("threshold=%.3f  false_positive_rate=%.4f", bundle["threshold"], report["false_positive_rate"])
    log.info("synthetic spike recall: 4sigma=%.3f 8sigma=%.3f", report["recall_4sigma"], report["recall_8sigma"])


if __name__ == "__main__":
    main()
