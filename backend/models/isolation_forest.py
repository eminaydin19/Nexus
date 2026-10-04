import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestModel:
    def __init__(self, forest: IsolationForest):
        self.forest = forest

    @classmethod
    def fit(cls, x: np.ndarray, seed: int = 42) -> "IsolationForestModel":
        forest = IsolationForest(
            n_estimators=150,
            max_samples=min(256, len(x)),
            random_state=seed,
            n_jobs=1,
        )
        forest.fit(x)
        return cls(forest)

    def error(self, x: np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(x)
