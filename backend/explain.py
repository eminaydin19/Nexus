import numpy as np

from backend.schema import FEATURE_SHORT


def contributions(scaled: np.ndarray) -> dict[str, float]:
    magnitude = np.abs(np.asarray(scaled, dtype=np.float64).ravel())
    total = float(magnitude.sum())
    if total <= 0 or not np.isfinite(total):
        share = np.full(len(FEATURE_SHORT), 1.0 / len(FEATURE_SHORT))
    else:
        share = magnitude / total
    return {name: round(float(value), 4) for name, value in zip(FEATURE_SHORT, share)}
