import argparse
import json
import pickle
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

STEP = 5.0
PER_DAY = int(86400 / STEP)
TAIL_Q = 99.5


class ECOD:

    def __init__(self, x: np.ndarray):
        self.sorted = np.sort(np.asarray(x, dtype=np.float64), axis=0)
        centered = self.sorted - self.sorted.mean(axis=0)
        self.right_skew = (centered**3).mean(axis=0) >= 0

    def score(self, x: np.ndarray) -> np.ndarray:
        n = len(self.sorted)
        left, right = np.empty_like(x, dtype=np.float64), np.empty_like(x, dtype=np.float64)
        for j in range(x.shape[1]):
            left[:, j] = np.searchsorted(self.sorted[:, j], x[:, j], side="right")
            right[:, j] = n - np.searchsorted(self.sorted[:, j], x[:, j], side="left")
        left = -np.log(np.maximum(left, 1.0) / (n + 1))
        right = -np.log(np.maximum(right, 1.0) / (n + 1))
        auto = np.where(self.right_skew, right, left)
        return np.maximum.reduce([left.sum(axis=1), right.sum(axis=1), auto.sum(axis=1)])


def ar1(rng: np.random.Generator, n: int, sigma: float, phi: float = 0.97) -> np.ndarray:
    noise = rng.normal(0, sigma * np.sqrt(1 - phi**2), n)
    out = np.empty(n)
    value = 0.0
    for i, e in enumerate(noise):
        value = phi * value + e
        out[i] = value
    return out


def bursts(rng: np.random.Generator, n: int, per_day: float, low_min: float, high_min: float) -> np.ndarray:
    out = np.zeros(n)
    for start in rng.integers(0, n, int(per_day * n / PER_DAY)):
        out[start : start + int(rng.uniform(low_min, high_min) * 60 / STEP)] = 1.0
    return out


def simulate(profile: str, days: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    n = days * PER_DAY
    t = np.arange(n) * STEP
    hour = (t / 3600) % 24
    weekday = (t / 86400 % 7).astype(int)
    load = (0.55 + 0.45 * np.sin((hour - 9) / 24 * 2 * np.pi)) * np.where(weekday >= 5, 0.6, 1.0) * (1 + 0.004 * t / 86400)
    burst = bursts(rng, n, 4, 3, 15)
    if profile == "web":
        cpu = 8 + 45 * load + 25 * burst + ar1(rng, n, 3)
        mem = 45 + 10 * load + 8 * ((t / (3 * 86400)) % 1) + ar1(rng, n, 0.6, 0.995)
        net = (300 + 4000 * load) * (1 + burst) * rng.lognormal(0, 0.25, n)
        lat = 20 * (1 + 2 * load**3) * (1 + 0.5 * burst) * rng.lognormal(0, 0.2, n)
    elif profile == "db":
        backup = ((hour >= 2) & (hour < 2 + 40 / 60)).astype(float)
        cpu = 5 + 25 * load + 35 * backup + 15 * burst + ar1(rng, n, 2)
        mem = 72 + 6 * load + ar1(rng, n, 0.4, 0.995)
        net = (200 + 1500 * load + 8000 * backup) * rng.lognormal(0, 0.3, n)
        lat = 3 * (1 + load) * (1 + backup) * rng.lognormal(0, 0.3, n)
    else:
        minute = (t / 60) % 60
        cron = ((minute % 15) < 2).astype(float)
        hourly = (minute < 5).astype(float)
        cpu = 4 + 3 * load + 45 * cron + 25 * hourly + ar1(rng, n, 2)
        mem = 35 + 15 * hourly + 8 * cron + ar1(rng, n, 0.8, 0.99)
        net = (50 + 800 * cron + 1500 * hourly) * rng.lognormal(0, 0.4, n)
        lat = 2 * (1 + cron) * rng.lognormal(0, 0.25, n)
    lat = lat * np.where(rng.random(n) < 0.002, rng.uniform(3, 6, n), 1.0)
    return np.column_stack([np.clip(cpu, 0, 100), np.clip(mem, 0, 100), np.maximum(net, 0), np.maximum(lat, 0.1)])


def inject(x: np.ndarray, scenario: str, start: int, rng: np.random.Generator) -> tuple[np.ndarray, int]:
    out = x.copy()
    minutes = {"cpu_saturated": 30, "memory_leak": 120, "exfiltration": 20, "latency_spike": 15, "subtle_cpu": 60,
               "dead_quiet": 30}[scenario]
    end = min(start + int(minutes * 60 / STEP), len(x))
    size = end - start
    if scenario == "cpu_saturated":
        out[start:end, 0] = rng.uniform(93, 100, size)
    elif scenario == "memory_leak":
        out[start:end, 1] += np.linspace(0, 100 - np.median(x[:, 1]), size)
        out[:, 1] = np.minimum(out[:, 1], 99.5)
    elif scenario == "exfiltration":
        out[start:end, 2] *= 20
    elif scenario == "latency_spike":
        out[start:end, 3] *= 15
    elif scenario == "subtle_cpu":
        out[start:end, 0] = np.minimum(out[start:end, 0] + 15, 100)
    elif scenario == "dead_quiet":
        out[start:end, 0] = rng.uniform(0, 1, size)
        out[start:end, 2] = rng.uniform(0, 5, size)
    return out, end


SCENARIOS = ("cpu_saturated", "memory_leak", "exfiltration", "latency_spike", "subtle_cpu", "dead_quiet")


def episodes_per_day(flagged: np.ndarray, days: int, in_a_row: int = 3) -> float:
    edges = np.flatnonzero(np.diff(np.concatenate([[0], flagged.astype(np.int8), [0]])))
    starts, ends = edges[::2], edges[1::2]
    return float(np.sum(ends - starts >= in_a_row)) / days


def configured_weights() -> dict:
    from backend.config import settings

    return {
        "iforest": settings.weight_isolation_forest,
        "lstm": settings.weight_lstm_ae,
        "transformer": settings.weight_transformer,
        "vae": settings.weight_vae,
    }


def rows_of(data: dict) -> dict:
    return {node: (np.arange(len(x)) * STEP, x) for node, x in data.items()}


def run(seed: int, train_days: int, test_days: int, epochs: int, injections: int) -> dict:
    from backend.models.ensemble import Ensemble
    from backend.models.features import FeatureScaler
    from training.train import train, windows_from

    profiles = ("web", "db", "batch")
    full = {p: simulate(p, train_days + test_days, seed * 100 + i) for i, p in enumerate(profiles)}
    history = {p: x[: train_days * PER_DAY].copy() for p, x in full.items()}
    future = {p: x[train_days * PER_DAY :].copy() for p, x in full.items()}

    history["web"], _ = inject(history["web"], "exfiltration", (train_days - 2) * PER_DAY, np.random.default_rng(seed))
    future["web"][:, 1] = np.minimum(future["web"][:, 1] + 4, 100)

    cpu0, wall0 = time.process_time(), time.time()
    bundle = train(rows_of(history), window=12, epochs=epochs, min_rows=500, seed=seed, source_name="bench")
    ensemble_train = {"cpu_s": time.process_time() - cpu0, "wall_s": time.time() - wall0}

    ensemble = Ensemble(configured_weights())
    ensemble.install_bundle(bundle)
    window = bundle["window"]
    scalers = {p: FeatureScaler.fit(h[: int(len(h) * 0.8)]) for p, h in history.items()}

    def ensemble_scores(p: str, raw: np.ndarray) -> np.ndarray:
        windows = windows_from([scalers[p].transform(raw)], window)
        parts = [
            ensemble.combine(ensemble.score_arrays(windows[i : i + 4096])) for i in range(0, len(windows), 4096)
        ]
        scores = np.concatenate(parts)
        return np.concatenate([np.zeros(window - 1), scores])

    cpu0, wall0 = time.process_time(), time.time()
    ecod = {p: ECOD(scalers[p].transform(h)) for p, h in history.items()}
    ecod_thresholds = {p: float(np.percentile(ecod[p].score(scalers[p].transform(h)), TAIL_Q)) for p, h in history.items()}
    ecod_train = {"cpu_s": time.process_time() - cpu0, "wall_s": time.time() - wall0}

    models = {
        "ensemble": (ensemble_scores, {p: ensemble.threshold_for(p) for p in profiles}),
        "ecod": (lambda p, raw: ecod[p].score(scalers[p].transform(raw)), ecod_thresholds),
    }
    clean = {name: {p: fn(p, future[p]) for p in profiles} for name, (fn, _) in models.items()}

    out = {"seed": seed, "train": {"ensemble": ensemble_train, "ecod": ecod_train},
           "report_fpr_in_bundle": bundle["report"]["false_positive_rate"], "models": {}}
    for name, (fn, thresholds) in models.items():
        fpr = {p: float(np.mean(clean[name][p] >= thresholds[p])) for p in profiles}
        episodes = {p: episodes_per_day(clean[name][p] >= thresholds[p], test_days) for p in profiles}
        matched = {p: float(np.percentile(clean[name][p], TAIL_Q)) for p in profiles}
        per_scenario = {}
        for scenario in SCENARIOS:
            own_hits, matched_hits, own_points, matched_points = [], [], [], []
            rng = np.random.default_rng(seed + 7)
            for p in profiles:
                for _ in range(injections):
                    start = int(rng.integers(window, len(future[p]) - 2000))
                    raw, end = inject(future[p], scenario, start, rng)
                    begin = max(0, start - window)
                    scores = fn(p, raw[begin:end])[start - begin :]
                    own = scores >= thresholds[p]
                    same = scores >= matched[p]
                    own_hits.append(own.mean() >= 0.2)
                    matched_hits.append(same.mean() >= 0.2)
                    own_points.append(own.mean())
                    matched_points.append(same.mean())
            per_scenario[scenario] = {
                "event_recall": float(np.mean(own_hits)),
                "point_recall": float(np.mean(own_points)),
                "event_recall_matched_fpr": float(np.mean(matched_hits)),
                "point_recall_matched_fpr": float(np.mean(matched_points)),
            }
        out["models"][name] = {
            "future_fpr": fpr,
            "false_alarms_per_node_day": float(np.mean(list(fpr.values())) * PER_DAY),
            "episodes_per_node_day_3_in_a_row": float(np.mean(list(episodes.values()))),
            "scenarios": per_scenario,
        }

    with tempfile.TemporaryDirectory() as tmp:
        ensemble_path, ecod_path = Path(tmp) / "ensemble.joblib", Path(tmp) / "ecod.pkl"
        import joblib

        joblib.dump(bundle, ensemble_path)
        with ecod_path.open("wb") as handle:
            pickle.dump({p: e.sorted for p, e in ecod.items()}, handle)
        out["bundle_mb"] = {"ensemble": ensemble_path.stat().st_size / 1e6, "ecod": ecod_path.stat().st_size / 1e6}
        out["serving"] = {
            name: json.loads(subprocess.check_output([sys.executable, __file__, "--serve", name, str(path)], text=True))
            for name, path in (("ensemble", ensemble_path), ("ecod", ecod_path))
        }
    return out


def peak_rss_mb() -> float:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) / 1024
    raise RuntimeError("VmHWM not found")


def serve(name: str, path: str) -> None:
    sample = np.array([40.0, 60.0, 1500.0, 25.0])
    calls = 2000
    if name == "ensemble":
        from backend.models.ensemble import Ensemble

        model = Ensemble(configured_weights())
        model.load(Path(path))
        for _ in range(model.window):
            model.predict("web", sample)
        predict = lambda: model.predict("web", sample)
    else:
        with open(path, "rb") as handle:
            sorted_by_node = pickle.load(handle)
        ecod = ECOD.__new__(ECOD)
        ecod.sorted = sorted_by_node["web"]
        ecod.right_skew = np.array([True, True, True, True])
        scaled = np.array([[0.1, 0.2, 0.3, 0.4]])
        predict = lambda: ecod.score(scaled)
    cpu0, wall0 = time.process_time(), time.perf_counter()
    for _ in range(calls):
        predict()
    print(json.dumps({
        "cpu_ms_per_snapshot": (time.process_time() - cpu0) / calls * 1000,
        "wall_ms_per_snapshot": (time.perf_counter() - wall0) / calls * 1000,
        "peak_rss_mb": peak_rss_mb(),
    }))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", nargs=2, metavar=("MODEL", "PATH"))
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--train-days", type=int, default=14)
    parser.add_argument("--test-days", type=int, default=3)
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--injections", type=int, default=20)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.serve:
        serve(*args.serve)
        return
    results = []
    for seed in range(1, args.seeds + 1):
        results.append(run(seed, args.train_days, args.test_days, args.epochs, args.injections))
        print(json.dumps(results[-1]), flush=True)
    if args.output:
        args.output.write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
