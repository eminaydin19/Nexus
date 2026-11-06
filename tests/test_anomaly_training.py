import numpy as np
import pytest

pytest.importorskip("sklearn")

from nexus_agent.anomaly import SSH_FEATURES, Forest
from nexus_agent.parsers import parse_ssh_line, parse_web_line
from scripts.replay import blocked, replay
from training.anomaly_sim import simulate
from training.train_anomaly import export_forest, fit, pick_threshold


def test_exported_forest_matches_scikit_learn():
    rng = np.random.default_rng(0)
    rows = rng.normal(size=(1000, len(SSH_FEATURES)))
    forest = fit(rows, 1)
    scorer = Forest(export_forest(forest, SSH_FEATURES, 0.5))
    check = rng.normal(size=(200, len(SSH_FEATURES))) * 2
    theirs = -forest.score_samples(check)
    ours = np.array([scorer.score(row) for row in check])
    assert np.max(np.abs(theirs - ours)) < 1e-3


def test_simulation_is_deterministic_and_ordered():
    a, b = simulate(9, customers=30, attacks=2), simulate(9, customers=30, attacks=2)
    assert a == b
    assert [r[0] for r in a] == sorted(r[0] for r in a)


def test_every_simulated_line_passes_the_real_parsers():
    records = simulate(9, customers=30, attacks=2)
    lines = [r for r in records if "by invalid user" not in r[2]]
    for ts, source, line, _, ip in lines:
        event = (parse_ssh_line if source == "ssh" else parse_web_line)(line, ts)
        assert event is not None and event.ip == ip, line


@pytest.mark.parametrize("scored, expected", [
    ([(0.9, True), (0.8, True), (0.7, False)], 0.8),
    ([(0.9, True), (0.8, False), (0.7, True)], 0.9),
])
def test_threshold_keeps_precision(scored, expected):
    assert pick_threshold(scored) == expected


def test_threshold_refuses_data_it_cannot_judge():
    with pytest.raises(ValueError):
        pick_threshold([(0.9, True)])
    with pytest.raises(ValueError):
        pick_threshold([(0.9, False)])


def test_replay_rules_catch_a_fast_attacker_and_fail2ban_sees_ssh_only():
    records = simulate(9, customers=10, attacks=2)
    lines = [(r[0], r[1], r[2]) for r in records]
    attackers = {r[4] for r in records if r[3] == "attack_ssh_fast"}
    assert attackers <= set(blocked(replay(lines, "rules")))
    banned = set(blocked(replay(lines, "fail2ban")))
    assert attackers <= banned
    assert not banned & {r[4] for r in records if r[3] == "attack_web_nikto"}


def test_training_uses_only_rows_past_the_gate():
    from training.train_anomaly import MIN_EVIDENCE, legit_rows

    data = {"ssh": {"a": ("customer_x", [[1.0], [2.0], [3.0]], [1, MIN_EVIDENCE, MIN_EVIDENCE + 1]),
                    "b": ("attack_y", [[9.0]], [MIN_EVIDENCE])}}
    assert legit_rows(data, "ssh", lambda label: label.startswith("customer")).tolist() == [[2.0], [3.0]]
