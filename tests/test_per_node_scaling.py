import numpy as np
import pytest

pytest.importorskip("torch")

from backend.config import settings
from backend.main import build_ensemble
from backend.models.features import FeatureScaler
from training.train import ordinary_mask, train


def _node(rng, rows, cpu, mem, net, latency):
    ts = np.arange(rows, dtype=float) * 10
    x = np.column_stack([
        cpu + rng.normal(0, 2, rows),
        mem + rng.normal(0, 2, rows),
        net * (1 + rng.normal(0, 0.05, rows)),
        latency * (1 + rng.normal(0, 0.05, rows)),
    ])
    return ts, x


@pytest.fixture(scope="module")
def trained():
    rng = np.random.default_rng(0)
    data = {
        "small": _node(rng, 300, 20, 40, 10, 5),
        "big": _node(rng, 300, 60, 70, 10000, 50),
        "tiny": _node(rng, 20, 30, 50, 100, 10),
        "flat": (np.arange(300, dtype=float) * 10, np.column_stack([
            20 + rng.normal(0, 2, 300), np.full(300, 50.0), 10 * (1 + rng.normal(0, 0.05, 300)), 5 * (1 + rng.normal(0, 0.05, 300)),
        ])),
    }
    bundle = train(data, 4, 1, 100, 1, "test")
    ens = build_ensemble(settings)
    ens.install_bundle(bundle)
    return bundle, ens


def test_bundle_has_scaler_per_big_node_and_default(trained):
    bundle, _ = trained
    assert set(bundle["scalers"]) == {"small", "big", "flat"}
    assert "default_scaler" in bundle


def _last_scaled(ens, node):
    return np.asarray(ens._buffers[node][-1])


def test_big_server_normal_load_is_not_anomalous_because_of_small_server(trained):
    bundle, ens = trained
    row = np.array([60.0, 70.0, 10000.0, 50.0])
    for _ in range(ens.window + 1):
        pred = ens.predict("big", row)
    assert pred.ensemble < ens.threshold
    assert ens._scaler_for("big") is not ens._default_scaler
    assert np.all(np.abs(_last_scaled(ens, "big")) < 0.5)
    default = FeatureScaler.from_dict(bundle["default_scaler"])
    assert np.abs(default.transform(row)).max() > 1.0


def test_unknown_node_uses_default_scaler(trained):
    bundle, ens = trained
    row = np.array([30.0, 50.0, 100.0, 10.0])
    assert ens.predict("new", row) is not None
    expected = FeatureScaler.from_dict(bundle["default_scaler"]).transform(row.reshape(1, -1))[0]
    assert np.allclose(_last_scaled(ens, "new"), expected)


def test_node_below_min_rows_uses_default_scaler(trained):
    bundle, ens = trained
    row = np.array([30.0, 50.0, 100.0, 10.0])
    ens.predict("tiny", row)
    expected = FeatureScaler.from_dict(bundle["default_scaler"]).transform(row.reshape(1, -1))[0]
    assert np.allclose(_last_scaled(ens, "tiny"), expected)


def test_flat_memory_feature_is_finite_and_not_instant_anomaly(trained):
    bundle, ens = trained
    scaler = FeatureScaler.from_dict(bundle["scalers"]["flat"])
    assert np.all(np.isfinite(scaler.scale)) and np.all(scaler.scale > 0)
    row = np.array([20.0, 50.0, 10.0, 5.0])
    for _ in range(ens.window + 1):
        pred = ens.predict("flat", row)
    scaled = _last_scaled(ens, "flat")
    assert np.all(np.isfinite(scaled)) and abs(scaled[1]) < 1.0
    assert pred.ensemble < ens.threshold


def test_prime_uses_node_scaler(trained):
    bundle, ens = trained
    raw = np.tile([60.0, 70.0, 10000.0, 50.0], (ens.window, 1))
    ens.prime("big", raw)
    expected = FeatureScaler.from_dict(bundle["scalers"]["big"]).transform(raw)
    assert np.allclose(np.stack(ens._buffers["big"]), expected)


def test_old_bundle_format_rejected(tmp_path):
    import joblib
    path = tmp_path / "old.joblib"
    joblib.dump({"format": 1}, path)
    with pytest.raises(ValueError):
        build_ensemble(settings).load(path)


def test_incident_in_newest_history_does_not_blind_calibration():
    rng = np.random.default_rng(0)
    ts, clean = _node(rng, 600, 20, 40, 100, 5)
    polluted = clean.copy()
    polluted[-120:-60] = np.column_stack([
        rng.uniform(0, 100, 60), rng.uniform(10, 90, 60), np.exp(rng.uniform(1, 13, 60)), np.exp(rng.uniform(0, 8, 60)),
    ])
    calibrated = train({"n": (ts, clean)}, 4, 1, 100, 1, "test")["calibration"]
    survived = train({"n": (ts, polluted)}, 4, 1, 100, 1, "test")["calibration"]
    for key in ("lstm", "transformer", "vae"):
        assert survived[key][1] < calibrated[key][1] * 3, (key, survived[key], calibrated[key])


def test_recurring_state_stays_in_calibration():
    values = np.concatenate([np.full(870, 1.0) + np.linspace(0, 0.01, 870), np.full(130, 50.0)])
    assert ordinary_mask(values)[-1]


def test_one_off_spike_leaves_calibration():
    values = np.concatenate([np.ones(990) + np.linspace(0, 0.01, 990), np.full(10, 50.0)])
    assert not ordinary_mask(values)[-1]


def test_large_incident_in_newest_rows_cannot_vouch_for_itself():
    older = np.ones(800) + np.linspace(0, 0.01, 800)
    values = np.concatenate([np.full(200, 50.0), older])
    assert not ordinary_mask(values, older)[0]
    assert ordinary_mask(values)[0]


def test_each_node_gets_its_own_threshold_and_holdout_rate(trained):
    bundle, ens = trained
    assert set(bundle["thresholds"]) >= {"small", "big", "flat"}
    assert bundle["report"]["eval_on"] == "holdout"
    assert 0.0 <= bundle["report"]["false_positive_rate"] <= 1.0
    assert ens.threshold_for("big") == bundle["thresholds"]["big"]
    assert ens.threshold_for("never-seen") == bundle["threshold"]
    ens.threshold_override = 0.7
    assert ens.threshold_for("big") == 0.7
    ens.threshold_override = 0.0
