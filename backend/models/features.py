import numpy as np

_MIN_SCALE = np.array([2.0, 2.0, 0.1, 0.1])
_CLIP = 15.0


def _prepare(x: np.ndarray) -> np.ndarray:
    out = np.asarray(x, dtype=np.float64).copy()
    out[..., 2:] = np.log1p(np.maximum(out[..., 2:], 0.0))
    return out


class FeatureScaler:
    def __init__(self, median: np.ndarray, scale: np.ndarray):
        self.median = np.asarray(median, dtype=np.float64)
        self.scale = np.asarray(scale, dtype=np.float64)

    @classmethod
    def fit(cls, x: np.ndarray) -> "FeatureScaler":
        prepared = _prepare(x)
        median = np.median(prepared, axis=0)
        q75, q25 = np.percentile(prepared, [75, 25], axis=0)
        scale = np.maximum((q75 - q25) / 1.349, _MIN_SCALE)
        return cls(median, scale)

    def transform(self, x: np.ndarray) -> np.ndarray:
        scaled = (_prepare(x) - self.median) / self.scale
        return np.clip(scaled, -_CLIP, _CLIP).astype(np.float32)

    def to_dict(self) -> dict:
        return {"median": self.median.tolist(), "scale": self.scale.tolist()}

    @classmethod
    def from_dict(cls, data: dict) -> "FeatureScaler":
        return cls(np.array(data["median"]), np.array(data["scale"]))
