import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np

from backend.explain import contributions as explain_contributions
from backend.models.features import FeatureScaler
from backend.models.isolation_forest import IsolationForestModel
from backend.models.lstm_autoencoder import LSTMAutoEncoder
from backend.models.transformer_autoencoder import TransformerAutoEncoder
from backend.models.vae import VAE
from backend.schema import FEATURE_SHORT

log = logging.getLogger(__name__)

MODEL_KEYS = ("iforest", "lstm", "vae", "transformer")
FLAG_SCORE = 0.5
BUNDLE_FORMAT = 1


def to_score(error: np.ndarray, lo: float, hi: float) -> np.ndarray:
    ratio = np.maximum(0.0, (np.asarray(error, dtype=np.float64) - lo) / max(hi - lo, 1e-9))
    return ratio / (ratio + 1.0)


@dataclass
class Prediction:
    scores: dict[str, float | None]
    ensemble: float
    is_anomaly: bool
    severity: str | None
    culprit: str
    flags: list[str] = field(default_factory=list)
    contributions: dict[str, float] = field(default_factory=dict)


class Ensemble:
    def __init__(self, weights: dict[str, float], threshold_override: float = 0.0, critical_score: float = 0.85):
        self.weights = self._normalize(weights)
        self.threshold_override = threshold_override
        self.critical_score = critical_score
        self.bundle: dict | None = None
        self.bundle_mtime = 0.0
        self._lock = threading.Lock()
        self._buffers: dict[str, deque] = {}

    @staticmethod
    def _normalize(weights: dict[str, float]) -> dict[str, float]:
        cleaned = {k: max(0.0, float(weights.get(k, 0.0))) for k in MODEL_KEYS}
        total = sum(cleaned.values())
        if total <= 0:
            raise ValueError("weights must have a positive sum")
        return {k: v / total for k, v in cleaned.items()}

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    @property
    def window(self) -> int:
        return int(self.bundle["window"]) if self.bundle else 0

    @property
    def threshold(self) -> float:
        if self.threshold_override > 0:
            return self.threshold_override
        return float(self.bundle["threshold"]) if self.bundle else 0.0

    def set_weights(self, weights: dict[str, float]) -> None:
        self.weights = self._normalize(weights)

    def load(self, path: Path) -> bool:
        if not path.exists():
            return False
        bundle = joblib.load(path)
        if bundle.get("format") != BUNDLE_FORMAT:
            raise ValueError(f"unsupported model bundle format: {bundle.get('format')}")
        with self._lock:
            self._install(bundle)
            self.bundle_mtime = path.stat().st_mtime
        log.info("model bundle loaded: %s", path)
        return True

    def reload_if_changed(self, path: Path) -> bool:
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            return False
        if mtime == self.bundle_mtime:
            return False
        try:
            return self.load(path)
        except Exception:
            log.exception("model bundle reload failed")
            self.bundle_mtime = mtime
            return False

    def install_bundle(self, bundle: dict) -> None:
        with self._lock:
            self._install(bundle)

    def _install(self, bundle: dict) -> None:
        self._scaler = FeatureScaler.from_dict(bundle["scaler"])
        self._iforest = IsolationForestModel(bundle["iforest"])
        self._lstm = LSTMAutoEncoder.from_state(bundle["lstm"])
        self._transformer = TransformerAutoEncoder.from_state(bundle["transformer"])
        self._vae = VAE.from_state(bundle["vae"])
        self._calibration = {k: tuple(v) for k, v in bundle["calibration"].items()}
        self.bundle = bundle
        self._buffers = {}

    def score_arrays(self, scaled_windows: np.ndarray) -> dict[str, np.ndarray]:
        last = scaled_windows[:, -1, :]
        return {
            "iforest": to_score(self._iforest.error(last), *self._calibration["iforest"]),
            "lstm": to_score(self._lstm.error(scaled_windows), *self._calibration["lstm"]),
            "transformer": to_score(self._transformer.error(scaled_windows), *self._calibration["transformer"]),
            "vae": to_score(self._vae.error(last), *self._calibration["vae"]),
        }

    def combine(self, scores: dict[str, np.ndarray | float | None]) -> np.ndarray:
        total = 0.0
        weight_sum = 0.0
        for key in MODEL_KEYS:
            value = scores.get(key)
            if value is None:
                continue
            total = total + self.weights[key] * np.asarray(value, dtype=np.float64)
            weight_sum += self.weights[key]
        return total / weight_sum

    def prime(self, node_id: str, raw_rows: np.ndarray) -> None:
        if not self.ready or len(raw_rows) == 0:
            return
        scaled = self._scaler.transform(raw_rows[-self.window :])
        with self._lock:
            self._buffers[node_id] = deque(scaled, maxlen=self.window)

    def predict(self, node_id: str, features: np.ndarray) -> Prediction | None:
        if not self.ready:
            return None
        with self._lock:
            scaled = self._scaler.transform(features.reshape(1, -1))[0]
            buffer = self._buffers.setdefault(node_id, deque(maxlen=self.window))
            buffer.append(scaled)
            last = scaled.reshape(1, -1)
            scores: dict[str, float | None] = {
                "iforest": float(to_score(self._iforest.error(last), *self._calibration["iforest"])[0]),
                "vae": float(to_score(self._vae.error(last), *self._calibration["vae"])[0]),
                "lstm": None,
                "transformer": None,
            }
            if len(buffer) == self.window:
                windows = np.stack(buffer)[None, :, :]
                scores["lstm"] = float(to_score(self._lstm.error(windows), *self._calibration["lstm"])[0])
                scores["transformer"] = float(to_score(self._transformer.error(windows), *self._calibration["transformer"])[0])

        ensemble = float(self.combine(scores))
        is_anomaly = ensemble >= self.threshold
        severity = None
        if is_anomaly:
            severity = "critical" if ensemble >= self.critical_score else "warning"
        culprit = FEATURE_SHORT[int(np.argmax(np.abs(scaled)))]
        flags = [k for k in MODEL_KEYS if scores[k] is not None and scores[k] >= FLAG_SCORE]
        return Prediction(
            scores={k: (round(v, 4) if v is not None else None) for k, v in scores.items()},
            ensemble=round(ensemble, 4),
            is_anomaly=is_anomaly,
            severity=severity,
            culprit=culprit,
            flags=flags,
            contributions=explain_contributions(scaled),
        )

    def info(self) -> dict:
        if not self.bundle:
            return {"ready": False}
        return {
            "ready": True,
            "trained_at": self.bundle["trained_at"],
            "window": self.window,
            "threshold": round(self.threshold, 4),
            "weights": {k: round(v, 4) for k, v in self.weights.items()},
            "report": self.bundle.get("report", {}),
        }
