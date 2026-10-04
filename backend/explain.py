import numpy as np

from backend.schema import FEATURE_SHORT


def contributions(scaled: np.ndarray) -> dict[str, float]:
    """Share (0..1, summing to 1) of the total deviation attributable to each metric.

    ``scaled`` is the feature vector after the training-time scaler, so each component is
    already expressed in units of normal variation and directly comparable.
    """
    magnitude = np.abs(np.asarray(scaled, dtype=np.float64).ravel())
    total = float(magnitude.sum())
    if total <= 0 or not np.isfinite(total):
        share = np.full(len(FEATURE_SHORT), 1.0 / len(FEATURE_SHORT))
    else:
        share = magnitude / total
    return {name: round(float(value), 4) for name, value in zip(FEATURE_SHORT, share)}
