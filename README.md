# Nexus

Self-hosted defense for your Linux servers. An agent on each server reads SSH and web logs, finds attackers from evidence, and blocks them with nftables. A central panel shows every server in one place.

**Top rule: not blocking a real customer matters more than catching every attack. When in doubt, Nexus does not block.**

No AWS account is needed. MIT licensed.

## What it does

| Attack | Reaction |
|---|---|
| SSH brute force | Blocks that IP on the SSH port |
| Web login brute force, vulnerability probing, exploit patterns | Blocks that IP on the web ports |
| Port scan | Alert. A full short block only with log evidence from the same IP, because a scan's source can be spoofed |
| Connection flood from one IP | Rate limit, never a block: many customers can share one address |
| Distributed flood | Alert only |
| Server metrics out of pattern (ML ensemble) | Alert only. A score never blocks anyone |

Blocks always expire, and the kernel holds the timer, so they end even if the agent crashes. Blocking and detection run on the server, so protection continues while central is down.

## What it does not do

**It cannot stop a large DDoS. Use Cloudflare or a similar service.** A flood that fills your server's network link has already done its damage by the time a firewall on that server sees it.

It also does not inspect traffic like a WAF, and it does not block at the CDN. Nexus cannot detect an attack that leaves no trace in the logs it reads or in its connection samples.

## Install

You need Docker with Compose 2.24 or newer for central. Each protected server needs Linux with systemd and Python 3.9 or newer: Ubuntu 20.04+, Debian 11+ or RHEL 8+.

**1. Install central.**

```bash
git clone https://github.com/eminaydin19/Nexus.git && cd Nexus && ./install.sh --domain nexus.example.com
```

With a domain, Caddy serves HTTPS on ports 80 and 443. Without one (`./install.sh`), central listens on `127.0.0.1:8000`, you reach it over an SSH tunnel, and only an agent on the same machine can connect. The installer generates the dashboard password, stores it in `.env` (mode 600) and prints it once. To upgrade, run `git pull` and then the installer again; secrets and data are kept.

**2. Add a server.** The panel gives you this command with a one-time token:

```bash
curl -fsSL https://nexus.example.com/install-agent.sh | NEXUS_ENROLL_TOKEN=<one-time-token> sudo --preserve-env=NEXUS_ENROLL_TOKEN bash
```

The token stays out of `ps` this way. sudo must allow keeping the variable: a sudoers rule for `ALL` already does, and a narrower one needs `SETENV`. If sudo refuses, run the same line from a root shell (`sudo -i`). Remove the agent with `--uninstall`.

## From observe to enforce

An agent starts in `observe`: it blocks nothing and lists what it would have blocked under Watch. After 7 days the panel shows that summary and asks for your approval. Nothing switches by itself, and you can switch earlier. The panel names the modes Watching, Blocking and Off.

To keep a server out of `enforce` whatever central says, set `NEXUS_MAX_MODE=observe` in `/etc/nexus-agent.env`. Central cannot change that file.

## How customers are protected

Nexus never blocks:

- Private, loopback, link-local, CGNAT and multicast addresses.
- Your allowlist. "This is a customer" in the panel adds to it and lifts any block.
- Central, the default gateway and the DNS servers in `/etc/resolv.conf`.
- IPs with an active SSH session or a successful SSH login in the last 24 hours.
- Published Cloudflare, Fastly and CloudFront ranges.
- Googlebot and Bingbot, verified by forward and reverse DNS.

Blocks stay narrow:

- A block applies to the attacked port. The only exception is a short full block for a scan with log evidence.
- Volume alone only slows an address down.
- IPv6 blocks apply to the `/64`.
- An IP with 20 successful page requests in the last hour and no scan traces gets 3 times the web thresholds.
- If there are more than 50 new blocks in 5 minutes or 2000 active blocks, the agent stops adding full blocks, alerts you and falls back to rate limits.

See [threshold tuning](docs/threshold-tuning.md) to change any threshold.

## Behind a CDN or proxy

The firewall sees the CDN's address, so blocking it would cut off everyone. When traffic comes from CDN ranges, web rules on that server only alert. SSH rules keep working. Nexus trusts `X-Forwarded-For` in logs only if you enable that explicitly.

## Agent permissions and central compromise

The agent runs as the `nexus-agent` user with `CAP_NET_ADMIN` and `CAP_DAC_READ_SEARCH`. It reads logs and manages one nftables table, `inet nexus`. It connects out to central and opens no port. Central can send it only three commands: unblock an IP, update the allowlist, change the mode. Central cannot run commands, write files, update the agent or request a block. [SECURITY.md](SECURITY.md) covers what an attacker controlling central could still do.

## SQLite or Postgres

Central stores data in SQLite by default, in one worker process. That suits a small fleet. For more servers, set `DATABASE_URL=postgresql+psycopg://user:pass@host/nexus` in `.env`.

## CloudWatch (optional)

Set `INGESTION_SOURCE=cloudwatch` with `AWS_REGION` and `EC2_INSTANCE_IDS` to also score CloudWatch metrics. See `deploy/cloudwatch-agent.json` and `deploy/latency_probe.sh`. Blocking still needs an agent.

## Configuration

`.env.example` lists central's settings. The main ones:

| Variable | Default | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | empty | Where alerts go |
| `ALERT_COOLDOWN_SECONDS` | 900 | Minimum gap between alerts for the same rule |
| `CRITICAL_SCORE` | 0.85 | ML score that sends a Slack alert. It never blocks |
| `RETENTION_DAYS` | 30 | How long history is kept |
| `RATE_LIMIT_PER_MINUTE` | 300 | Requests per minute per client IP |

`/metrics` serves Prometheus metrics behind the dashboard's basic auth.

## Tests

```bash
scripts/test.sh          # unit tests
scripts/test.sh --nft    # real nftables in a container
scripts/test.sh --e2e    # installers in systemd containers
scripts/test.sh --panel  # panel in a real browser
tests/e2e/run.sh         # real attacks and customers, on SQLite and Postgres
```

The scenarios change one kernel-wide setting while they run, `net.netfilter.nf_log_all_netns`, and restore it afterwards.

## License

[MIT](LICENSE). The bundled Archivo font uses the [SIL Open Font License](frontend/fonts/OFL.txt).
