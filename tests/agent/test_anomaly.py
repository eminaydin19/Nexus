from __future__ import annotations

import json
import math

import pytest

from nexus_agent import anomaly
from nexus_agent.anomaly import SSH_FEATURES, WEB_FEATURES, Behavior, Forest, average_path, load_models


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def spec(features, threshold=0.5):
    tree = {"f": [0, -2, -2], "t": [5.0, -2.0, -2.0], "l": [1, -1, -1], "r": [2, -1, -1], "n": [256, 255, 1]}
    return {"threshold": threshold, "features": list(features), "max_samples": 256, "trees": [tree]}


def model_file(tmp_path, **override):
    data = {"web": spec(WEB_FEATURES), "ssh": spec(SSH_FEATURES)}
    data.update(override)
    path = tmp_path / "model.json"
    path.write_text(json.dumps(data))
    return path


def test_average_path_known_values():
    assert average_path(1) == 0.0 and average_path(2) == 1.0
    assert average_path(256) == pytest.approx(10.2448, abs=1e-3)


def test_isolated_row_scores_higher():
    forest = Forest(spec(WEB_FEATURES))
    assert forest.score([9.0] * 9) > forest.score([1.0] * 9)
    assert forest.score([9.0] * 9) == pytest.approx(2.0 ** (-1.0 / average_path(256)))


def test_load_valid_model(tmp_path):
    assert set(load_models(model_file(tmp_path))) == {"web", "ssh"}


@pytest.mark.parametrize("content", ["", "{", "[]", '{"web": {}}', '{"web": 5, "ssh": 5}'])
def test_malformed_model_means_no_model(tmp_path, content):
    path = tmp_path / "model.json"
    path.write_text(content)
    assert load_models(path) == {}


def test_missing_model_means_no_model(tmp_path):
    assert load_models(tmp_path / "absent.json") == {}


def test_model_with_other_features_is_refused(tmp_path):
    assert load_models(model_file(tmp_path, ssh=spec(("other",)))) == {}


def test_model_without_trees_is_refused(tmp_path):
    empty = spec(SSH_FEATURES)
    empty["trees"] = []
    assert load_models(model_file(tmp_path, ssh=empty)) == {}


def test_web_features_describe_behavior():
    clock = Clock()
    b = Behavior(clock=clock)
    b.note_web("ip", "/", 200, "ua", False)
    clock.t += 30
    b.note_web("ip", "/a.css", 200, "ua", False)
    clock.t += 30
    b.note_web("ip", "/.env", 404, None, True)
    row = dict(zip(WEB_FEATURES, b.features("web", "ip")))
    assert b.evidence("web", "ip") == 1
    assert row["requests_per_min"] == pytest.approx(3.0)
    assert row["log_requests"] == pytest.approx(math.log1p(3))
    assert row["distinct_path_ratio"] == 1.0
    assert row["err4xx_ratio"] == pytest.approx(1 / 3)
    assert row["static_ratio"] == pytest.approx(1 / 3)
    assert row["no_user_agent_ratio"] == pytest.approx(1 / 3)
    assert row["interval_cv"] == 0.0
    assert row["browser_ratio"] == 0.0


def test_ssh_lines_of_one_connection_count_once():
    clock = Clock()
    b = Behavior(clock=clock)
    b.note_ssh("ip", "bob", True, 5000, False)
    b.note_ssh("ip", "bob", False, 5000, False)
    assert b.evidence("ssh", "ip") == 1
    b.note_ssh("ip", "bob", False, 5000, True)
    assert b.evidence("ssh", "ip") == 2
    b.note_ssh("ip", "amy", True, 5001, False)
    row = dict(zip(SSH_FEATURES, b.features("ssh", "ip")))
    assert row["distinct_users"] == 2.0
    assert row["invalid_ratio"] == pytest.approx(2 / 3)


def test_counters_reset_after_an_hour():
    clock = Clock()
    b = Behavior(clock=clock)
    b.note_ssh("ip", "a", True, 1, False)
    clock.t += anomaly.WINDOW
    b.note_ssh("ip", "a", True, 2, False)
    assert b.evidence("ssh", "ip") == 1


def test_tracked_addresses_stay_bounded():
    b = Behavior(max_ips=10, clock=Clock())
    for i in range(50):
        b.note_web("ip%d" % i, "/", 200, "ua", False)
    assert len(b._ips) == 10
    assert b.evidence("web", "ip0") == 0


def test_path_memory_stays_bounded():
    b = Behavior(clock=Clock())
    for i in range(anomaly.MAX_PATHS * 2):
        b.note_web("ip", "/%d" % i, 404, "ua", False)
    assert len(b._ips[("web", "ip")].paths) == anomaly.MAX_PATHS


def test_forget_clears_both_channels():
    b = Behavior(clock=Clock())
    b.note_web("ip", "/", 200, "ua", True)
    b.note_ssh("ip", "a", True, 1, False)
    b.forget("ip")
    assert b.evidence("web", "ip") == 0 and b.evidence("ssh", "ip") == 0
