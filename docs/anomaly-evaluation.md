# Anomaly-driven blocking: evaluation

A block from the anomaly path needs log evidence and an odd behavior together. This page gives what was measured, and what was not.

**Every number below comes from simulated log lines, written by the same project that built the model. It is not a result from a real server.** The simulated customers and attackers differ in the ways we assumed they would, so this shows the system works under those assumptions. It does not show how often real customers would be blocked.

## Target

| Measure | Target | Simulated result, rules + model |
|---|---|---|
| Recall, all attack classes | at least 95% | **87.7%, target not met** |
| Block precision | at least 99% | 99.4% (CI 98.8-99.7), met |

Web classes reached 100%. The gap is in SSH, see below.

## Results

5 unseen seeds with 200 attackers per class and 3000 customers. Each cell gives the share of those addresses that got blocked, the counts, and the 95% Wilson interval.

| Measure | fail2ban | rules | model | hybrid |
|---|---|---|---|---|
| attack_ssh_fast | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) |
| attack_ssh_root_only | 83.5% (167/200, CI 77.7-88.0) | 0.0% (0/200, CI 0.0-1.9) | 26.0% (52/200, CI 20.4-32.5) | 26.0% (52/200, CI 20.4-32.5) |
| attack_ssh_slow | 0.0% (0/200, CI 0.0-1.9) | 0.0% (0/200, CI 0.0-1.9) | 63.5% (127/200, CI 56.6-69.9) | 63.5% (127/200, CI 56.6-69.9) |
| attack_web_gobuster | 0.0% (0/200, CI 0.0-1.9) | 82.0% (164/200, CI 76.1-86.7) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) |
| attack_web_login_slow | 0.0% (0/200, CI 0.0-1.9) | 0.0% (0/200, CI 0.0-1.9) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) |
| attack_web_nikto | 0.0% (0/200, CI 0.0-1.9) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) |
| attack_web_slow_probe | 0.0% (0/200, CI 0.0-1.9) | 0.0% (0/200, CI 0.0-1.9) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) |
| attack_web_spa_scan | 0.0% (0/200, CI 0.0-1.9) | 0.0% (0/200, CI 0.0-1.9) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) |
| attack_web_sqlmap | 0.0% (0/200, CI 0.0-1.9) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) | 100.0% (200/200, CI 98.1-100.0) |
| customer_api | 0.0% (0/250, CI 0.0-1.5) | 0.0% (0/250, CI 0.0-1.5) | 100.0% (250/250, CI 98.5-100.0) | 0.0% (0/250, CI 0.0-1.5) |
| customer_browser | 0.0% (0/1500, CI 0.0-0.3) | 0.0% (0/1500, CI 0.0-0.3) | 100.0% (1500/1500, CI 99.7-100.0) | 0.0% (0/1500, CI 0.0-0.3) |
| customer_curious | 0.0% (0/250, CI 0.0-1.5) | 0.0% (0/250, CI 0.0-1.5) | 100.0% (250/250, CI 98.5-100.0) | 0.0% (0/250, CI 0.0-1.5) |
| customer_login_typos | 0.0% (0/250, CI 0.0-1.5) | 0.0% (0/250, CI 0.0-1.5) | 100.0% (250/250, CI 98.5-100.0) | 0.4% (1/250, CI 0.1-2.2) |
| customer_ssh_keys | 49.6% (124/250, CI 43.5-55.8) | 0.0% (0/250, CI 0.0-1.5) | 0.4% (1/250, CI 0.1-2.2) | 0.4% (1/250, CI 0.1-2.2) |
| customer_ssh_typos | 45.6% (114/250, CI 39.5-51.8) | 0.0% (0/250, CI 0.0-1.5) | 0.0% (0/250, CI 0.0-1.5) | 0.0% (0/250, CI 0.0-1.5) |
| customer_ssh_wrong_user | 0.0% (0/250, CI 0.0-1.5) | 0.0% (0/250, CI 0.0-1.5) | 3.2% (8/250, CI 1.6-6.2) | 3.2% (8/250, CI 1.6-6.2) |
| **Recall, all attacks** | 20.4% (367/1800, CI 18.6-22.3) | 42.4% (764/1800, CI 40.2-44.7) | 87.7% (1579/1800, CI 86.1-89.2) | 87.7% (1579/1800, CI 86.1-89.2) |
| **Share of customers blocked** | 7.9% (238/3000, CI 7.0-9.0) | 0.0% (0/3000, CI 0.0-0.1) | 75.3% (2259/3000, CI 73.7-76.8) | 0.3% (10/3000, CI 0.2-0.6) |
| **Block precision** | 60.7% (367/605, CI 56.7-64.5) | 100.0% (764/764, CI 99.5-100.0) | 41.1% (1579/3838, CI 39.6-42.7) | 99.4% (1579/1589, CI 98.8-99.7) |
| Median time to block | 12 s | 10 s | 0 s | 5 s |

Rules + model blocked 815 attackers that rules alone missed.

The fail2ban column counts failed lines with default settings (5 tries in 10 minutes), since the real jail settings were not read. It blocks admins because the simulated ones mistype at that rate.

The model column is not a fair test of a model running alone. The model is trained only for addresses already past the evidence gate, so it scores ordinary visitors meaninglessly. It shows why the gate must stay.

## Where it falls short

- **`attack_ssh_root_only`, 26%:** a few tries on the `root` account look the same as an admin whose key is refused. This is the top rule at work, and fail2ban catches more here only by also blocking admins.
- **`attack_ssh_slow`, 63.5%:** a slow dictionary attack resembles a person trying usernames on a server. The cost of catching more shows in `customer_ssh_wrong_user`, already 3.2%.
- **`customer_ssh_wrong_user`, 3.2%:** an admin trying 3 or 4 usernames can lose SSH for 15 minutes. Test this on real traffic before enabling blocks.

## How the numbers were reached

Four rounds, each reported on seeds it had never seen:

| Round | Change | Recall | Precision |
|---|---|---|---|
| 1 | Train on all customer rows | 64.4% | 98.8% |
| 2 | Add browser share, drop first requests | 71.1% | 99.1% |
| 3 | Add suspicious share | 60.4% | 98.0% |
| 4 | Train only on customers past the evidence gate | 87.7% | 99.4% |

Round 4 was chosen by comparing strategies on separate validation seeds. Rounds 1-3 used up their report seeds, so these results were tuned against the simulator's design, even though each final seed was new.

## End to end

`tests/e2e/scenarios.py` runs real `sshd`, nginx and nftables with the flag on. A real SSH attacker trying 8 usernames was blocked on port 22 only in 10 seconds. A client requesting 6 scanner paths was blocked on the web port in 5 seconds, and a customer kept getting pages. A customer mistyping a password 3 times stayed unblocked.

## Not measured

- Real server traffic. `scripts/export_real_events.py` and `eval_anomaly.py --real` are ready and have not run.
- The 14-day observe period that the design requires before enabling blocks on a real server.
- Real attack tools (nikto, gobuster, hydra, sqlmap). Their simulated lines imitate them.
- Attackers who imitate browsers by fetching assets. The model relies on that difference.
- Addresses behind Cloudflare, which still only produce alerts.

## Measure a real server

This reads SSH logs, web container logs and fail2ban's bans, and writes no file on the server. Addresses, usernames, ordinary paths and user agents leave only as HMAC values under a key made for the run and never stored. Query strings never leave.

```bash
python3 scripts/export_real_events.py <web-container>... | ssh root@server python3 - > events.jsonl
docker run --rm -v "$PWD":/app -w /app --entrypoint python nexus-test scripts/eval_anomaly.py --real events.jsonl
```

Labels on real data come from rules: an address that logged in is a customer, an address with 2 or more invalid usernames and no login is an attacker. They are an estimate, not ground truth.

## Reproduce

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint python nexus-test -m training.train_anomaly --output nexus_agent/data/anomaly_model.json
docker run --rm -v "$PWD":/app -w /app --entrypoint python nexus-test scripts/eval_anomaly.py
```
