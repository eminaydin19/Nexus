# Nexus

Real-time anomaly detection and active defense for Linux servers.

An agent on each server reads SSH and web logs, finds attackers from evidence and behavior, and blocks them in the kernel with nftables. A self-hosted panel shows every server in one place. No cloud account is needed.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

![Nexus panel](assets/nexus_dashboard.png)

**Top rule: not blocking a real customer matters more than catching every attack. When in doubt, Nexus does not block.**

## How it works

```text
SSH and web logs ──> rules ───────────────┐
                 ──> per-IP anomaly model ─┴─> customer protections ──> nftables block
                                                      │
                                                      └──> panel and Slack alerts
```

- Detection and blocking run on the server, so protection continues while central is down.
- Every block expires, and the kernel holds the timer, so a block ends even if the agent crashes.
- Central cannot run commands on a server, update an agent or request a block. See [SECURITY.md](SECURITY.md).

## What it detects

| Attack | Response |
|---|---|
| SSH brute force | Blocks the address on the SSH port |
| Web login brute force, vulnerability probing, exploit patterns | Blocks the address on the web ports |
| Slow attacks under the rule thresholds (anomaly model) | Alerts by default. With `NEXUS_RULE_ANOMALY_BLOCK=1`, blocks the attacked port for 15 minutes |
| Port scan | Alerts. A short full block only with log evidence from the same address |
| Connection flood from one address | Rate limit, never a block |
| Distributed flood | Alerts only |
| Unusual server metrics (ML ensemble) | Alerts only |

The anomaly model never blocks on its score alone. It also needs at least 3 suspicious log events from the address, and every customer protection still applies.

## Results

| Measure | fail2ban | Rules | Rules + model | Target |
|---|---|---|---|---|
| Attacks blocked (recall) | 20.4% | 42.4% | **87.7%** | 95%, not met |
| Blocks that hit an attacker (precision) | 60.7% | 100% | **99.4%** | 99%, met |
| Customers blocked | 7.9% | 0% | 0.3% | |

**These numbers come from simulated logs, not from a real server.** Slow SSH attacks are the gap: they look like a person trying usernames. The [evaluation](docs/anomaly-evaluation.md) has per-attack results, confidence intervals and what was not measured.

Real attacks also run against real `sshd`, nginx and nftables in `tests/e2e`.

## Install

Central needs Docker with Compose 2.24 or newer. Each protected server needs Linux with systemd and Python 3.9 or newer: Ubuntu 20.04+, Debian 11+ or RHEL 8+.

**1. Install central.**

```bash
git clone https://github.com/eminaydin19/Nexus.git && cd Nexus && ./install.sh --domain nexus.example.com
```

With a domain, Caddy serves HTTPS on ports 80 and 443. Without one, central listens on `127.0.0.1:8000`, and you reach it over an SSH tunnel. The installer prints the dashboard password once. To upgrade, run `git pull` and the installer again.

**2. Add a server.** The panel gives you this command with a one-time token:

```bash
curl -fsSL https://nexus.example.com/install-agent.sh | NEXUS_ENROLL_TOKEN=<one-time-token> sudo --preserve-env=NEXUS_ENROLL_TOKEN bash
```

If sudo refuses to keep the variable, run the line from a root shell. Remove the agent with `--uninstall`.

**3. Watch, then enforce.** An agent starts in `observe`: it blocks nothing and lists what it would have blocked. After 7 days the panel shows a summary and asks for your approval. Nothing switches by itself.

To keep a server out of `enforce` whatever central says, set `NEXUS_MAX_MODE=observe` in `/etc/nexus-agent.env`.

To try anomaly blocking, set `NEXUS_RULE_ANOMALY_BLOCK=1` in the same file and stay in `observe`. Its decisions appear under Watch, and nobody is blocked.

## Who is never blocked

- Private, loopback, link-local, CGNAT and multicast addresses
- Your allowlist. "This is a customer" in the panel adds to it and lifts any block
- Central, the default gateway and the DNS servers in `/etc/resolv.conf`
- Addresses with an active SSH session or a successful SSH login in the last 24 hours
- Published Cloudflare, Fastly and CloudFront ranges
- Googlebot and Bingbot, verified by forward and reverse DNS

Blocks also stay narrow:

- A block covers the attacked port. The only exception is a short full block for a scan with log evidence
- IPv6 blocks apply to the `/64`
- An address with 20 successful page requests in the last hour and no scan traces gets 3 times the web thresholds
- Above 50 new blocks in 5 minutes or 2000 active blocks, the agent stops adding full blocks, alerts you and falls back to rate limits

## Behind a CDN or proxy

The firewall sees the CDN's address, so blocking it would cut off everyone. Traffic from CDN ranges only produces alerts from web rules, and SSH rules keep working. Nexus never reads `X-Forwarded-For` from logs, because a client can write anything there.

An address with 200 successful requests from 10 different browsers in the last hour also gets alerts instead of web blocks. Add your own proxy to the allowlist anyway.

Behind your own Caddy, enable a JSON access log and set `NEXUS_WEB_LOG_FORMAT=caddy-json` and `NEXUS_WEB_LOGS=<path>`. The client address comes from Caddy's `client_ip`, so your `trusted_proxies` setting must be right.

## Limits

- **It cannot stop a large DDoS. Use Cloudflare or a similar service.** A flood that fills your network link has done its damage before a firewall on that server sees it.
- It is not a WAF, and it does not block at the CDN.
- It cannot detect an attack that leaves no trace in its logs or connection samples.

## Configuration

`.env.example` lists central's settings. The main ones:

| Variable | Default | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | empty | Where alerts go |
| `ALERT_COOLDOWN_SECONDS` | 900 | Minimum gap between alerts for the same rule |
| `CRITICAL_SCORE` | 0.85 | ML score that sends a Slack alert. It never blocks |
| `RETENTION_DAYS` | 30 | How long history is kept |
| `RATE_LIMIT_PER_MINUTE` | 300 | Requests per minute per client address |
| `DATABASE_URL` | SQLite | Set `postgresql+psycopg://user:pass@host/nexus` for a larger fleet |

Agent thresholds are in [threshold tuning](docs/threshold-tuning.md). `/metrics` serves Prometheus metrics behind the dashboard's basic auth.

To also score CloudWatch metrics, set `INGESTION_SOURCE=cloudwatch` with `AWS_REGION` and `EC2_INSTANCE_IDS`. Blocking still needs an agent.

## Tests

| Command | What it runs |
|---|---|
| `scripts/test.sh` | Unit tests |
| `scripts/test.sh --nft` | Real nftables in a container |
| `scripts/test.sh --panel` | The panel in a real browser |
| `scripts/test.sh --e2e` | Installers in systemd containers |
| `tests/e2e/run.sh` | Real attacks and customers on SQLite and Postgres |

`tests/e2e/run.sh` changes one kernel-wide setting, `net.netfilter.nf_log_all_netns`, and restores it afterwards.

## License

[MIT](LICENSE). Bundled third-party files keep their own licenses: [Chart.js](https://github.com/chartjs/Chart.js) under MIT and the [Archivo font](frontend/fonts/OFL.txt) under the SIL Open Font License.
