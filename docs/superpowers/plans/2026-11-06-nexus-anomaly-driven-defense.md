# Anomaly-Driven Defense Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an anomaly model part of the block decision, and measure the result honestly.

**Architecture:** The agent keeps per-IP behavior counters. Once an IP has log evidence, a bundled Isolation Forest scores its behavior in pure Python, and a block needs both. Training runs offline with scikit-learn and exports JSON.

**Tech Stack:** Python 3.9 stdlib on the agent; scikit-learn in `training/` only.

**Spec:** `docs/superpowers/specs/2026-11-06-nexus-anomaly-driven-defense-design.md`

## Global Constraints

- Top rule: not blocking a customer matters more than catching every attack.
- No new agent dependency. Agent code must run on Python 3.9.
- A score alone never blocks. Central cannot send a block or a model.
- Blocks cover only the attacked port, base TTL 900 seconds.
- Real-server limits for today: no `enforce`, no 14-day shadow run, no agent install, no Caddy change.
- Model features exclude the evidence count. They include the suspicious share of requests, because without it a simulated scanner modeled on real server traffic scored 0% recall.
- Simulated results are labeled simulated. Report data is never used to set a threshold.

## Review Focus

- A legitimate user mistyping an SSH password three times stays unblocked. Test in Task 2.
- A browser user with many assets hitting one probe-like path stays unblocked. Test in Task 2.
- An IP with protection (allowlist, recent SSH, CDN, shared) is never blocked by the new path. Test in Task 2.
- A malformed or missing model file disables the new path, and rules keep working. Test in Task 1.
- A forged `client_ip` cannot arrive through a non-Caddy log line. Test in Task 3.

---

### Task 1: Features and pure-Python scorer

**Files:** Create `nexus_agent/anomaly.py`, `tests/agent/test_anomaly.py`.

**Interfaces:**
- Produces: `WEB_FEATURES`, `SSH_FEATURES`; `Forest.score(row: Sequence[float]) -> float`; `load_models(path=None) -> Dict[str, Forest]`, empty on any problem; `Behavior(max_ips, clock)` with `note_web(ip, path, status, ua, is_evidence) -> None`, `note_ssh(ip, user, invalid, is_evidence) -> None`, `evidence(channel, ip) -> int`, `features(channel, ip) -> List[float]`, `forget(ip)`.

- [ ] Tests: scorer matches scikit-learn on 200 random rows within 1e-9, in a training-side test; missing and malformed model give `{}`; counters reset after 3600 seconds; IP count stays within `max_ips`.
- [ ] Implement. Isolation Forest score is `2 ** (-mean_path / c(n))`.
- [ ] Commit.

### Task 2: Rule engine wiring

**Files:** Modify `nexus_agent/rules.py`, `frontend/js/wording.js`, `docs/threshold-tuning.md`. Test in `tests/agent/test_rules.py`.

**Interfaces:** Consumes Task 1. Produces rules `anomaly_ssh`, `anomaly_web`; `RuleConfig.anomaly_block: int = 0`, `anomaly_min_evidence: int = 3`, `ttl_anomaly_ssh = ttl_anomaly_web = 900`. `RuleEngine(cfg, protector, clock, models=None)`.

- [ ] Tests: the Review Focus cases; sub-threshold SSH attacker fires `anomaly_ssh` with `block_port` on SSH ports when the flag is on and `alert` when off; probes answered with 200 fire `anomaly_web`; evidence requirement scales with `threshold_multiplier`; no anomaly decision when a rule already fired on that event; without models behavior is unchanged.
- [ ] Implement through the existing `_fire`, so every protection applies.
- [ ] Commit.

### Task 3: Caddy JSON log

**Files:** Modify `nexus_agent/parsers.py`, `nexus_agent/config.py`, `nexus_agent/main.py`, `nexus_agent/collectors.py`, `README.md`. Test in `tests/agent/test_parsers.py`.

**Interfaces:** Produces `parse_caddy_line(line, now) -> Optional[LogEvent]`; `caddy_line_is_stale(line, now) -> bool`; setting `NEXUS_WEB_LOG_FORMAT=caddy-json`, with files through `NEXUS_WEB_LOGS`.

- [ ] Tests: reads `request.client_ip`, not any header; invalid JSON, non-access lines and bad types return `None`; `request.remote_ip` different from `client_ip` sets `via_proxy`, and web rules only alert.
- [ ] Implement. Only an explicit setting selects this format.
- [ ] Commit.

### Task 4: Training data and model

**Files:** Create `training/anomaly_sim.py`, `training/train_anomaly.py`, `nexus_agent/data/anomaly_model.json`. Test `tests/test_anomaly_training.py`.

**Interfaces:** Produces `simulate(seed) -> Iterator[Tuple[float, str, str, str]]` of `(ts, source, line, label)`, where label is `customer`, or an attack class. `python -m training.train_anomaly --output PATH` trains on seeds 1-5, sets thresholds on seeds 6-7 for 99% precision, and writes the JSON.

- [ ] Tests: the export reproduces scikit-learn's scores; seeds are deterministic; the model file fits under 1 MB.
- [ ] Implement real log formats, so lines pass through the real parsers. Customers: browsers with assets, API clients, typing admins, a key-juggling admin. Attacks: fast and slow SSH, dictionary SSH, nikto-style, gobuster-style, sqlmap-style, slow probes.
- [ ] Commit.

### Task 5: Replay and evaluation

**Files:** Create `scripts/replay.py`, `scripts/eval_anomaly.py`, `docs/anomaly-evaluation.md`. Test `tests/test_replay.py`.

**Interfaces:** Consumes Tasks 1-4. Produces `replay(lines, system, models) -> List[Decision]` where `system` is `rules`, `model`, or `hybrid`; a fail2ban-equivalent counter with the server's jail settings.

- [ ] Tests: replay agrees with feeding the engine directly; Wilson interval matches known values.
- [ ] Evaluate on seeds never used before, per attack class, with intervals, and write the report.
- [ ] Commit.

### Task 6: Real SSH evaluation (only with the user's approval)

**Files:** Create `scripts/export_ssh_events.py`. Modify `docs/anomaly-evaluation.md`.

**Interfaces:** Runs on the server through stdin, writes no file there, and prints JSON lines with HMAC-hashed IPs and usernames, using a key generated for the run and discarded. Label: `legit` if the IP ever logged in; `attacker` if never, with at least 2 invalid-user attempts; otherwise `unclear`.

- [ ] Run and replay through all systems, and compare with fail2ban's actual bans.
- [ ] Write results, stating that labels are rule-based.
- [ ] Commit.

### Task 7: End-to-end and documents

**Files:** Modify `tests/e2e/scenarios.py`, `README.md`, `SECURITY.md`.

- [ ] Add scenarios with the flag on: real sub-threshold SSH attacker gets a kernel block; a real customer stays reachable.
- [ ] Run unit, `--nft`, `--panel`, `--e2e`, then `tests/e2e/run.sh`.
- [ ] Update documents to state what was and was not verified. Commit.
