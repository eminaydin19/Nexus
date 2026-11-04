<div align="center">
  <h1>Nexus Security</h1>
  <p><strong>Real-time Anomaly Detection & Active Defense for AWS Cloud Infrastructure</strong></p>
  <img src="https://img.shields.io/badge/Production-Ready-success?style=flat-square" />
  <img src="https://img.shields.io/badge/AWS-CloudWatch-orange?style=flat-square&logo=amazon-aws" />
</div>

<br>

Nexus is an advanced security and telemetry analysis system designed for cloud environments. It continuously ingests real-time metrics, analyzes them using a multi-model machine learning ensemble, and actively defends your infrastructure by automatically quarantining malicious actors at the firewall level.

## Architecture

1. **Ingestion:** Receives telemetry securely via CloudWatch or agent APIs using strict rate limits and API key validation.
2. **Analysis:** The machine learning ensemble evaluates metrics (CPU, Memory, Network, Latency). It computes an aggregate Ensemble Score.
3. **Defense:** If the score exceeds the critical threshold, Nexus triggers Safe Mode and injects block rules into the host's firewall.
4. **Observability:** Metrics are exposed via a Prometheus `/metrics` endpoint, and events are logged to a local SQLite database for the dashboard.

## Key Capabilities

- **Multi-Model ML Ensemble:** Uses a combination of Isolation Forest, LSTM Autoencoders, Variational Autoencoders (VAE), and Time-Series Transformers to detect both statistical outliers and complex behavioral anomalies.
- **Active Defense Firewall:** Automatically blocks malicious IPs in real-time. Supports `iptables`, `nftables`, and macOS `pfctl`. Includes a Safe Mode to protect APIs during critical attacks.
- **AWS CloudWatch Integration:** Directly ingests metrics and logs from AWS CloudWatch using Boto3. 100% production-ready.
- **Real-time Dashboard:** A responsive WebSockets-based dashboard with Deviation Drivers and active defense management.
- **High Performance:** CPU-bound inference pipeline optimized for edge nodes and small AWS EC2 instances to prevent memory bottlenecks.
- **Continuous Learning:** The system automatically retrains its neural networks every 24 hours in the background without downtime.

## Installation

Nexus runs on any Linux server with Docker and Docker Compose 2.24 or newer. AWS is not needed.

```bash
git clone https://github.com/eminaydin19/Nexus.git && cd Nexus && ./install.sh --domain nexus.example.com
```

With a domain, Caddy serves HTTPS on ports 80 and 443. Without one (`./install.sh`), Nexus listens on `127.0.0.1:8000` only, and you reach it over an SSH tunnel; only an agent on the same machine can connect then.

The installer generates the dashboard password, stores it in `.env` (mode 600) and prints it once. To upgrade, run `git pull` first and then the installer again: it rebuilds Nexus and keeps your secrets and data. At the end it prints where to log in and how to add your first server:

```bash
curl -fsSL https://nexus.example.com/install-agent.sh | sudo bash -s -- --token <one-time-token>
```

The agent needs systemd and Python 3.9 or newer. It starts in observe mode: no traffic is blocked until you enable enforce in the panel. Remove it with `--uninstall`. Python 3.9 can come from your distribution, for example `python3.9` on Ubuntu 20.04 or `python39` on the RHEL 8 family. CloudWatch ingestion remains optional, see `deploy/cloudwatch-agent.json` and `deploy/latency_probe.sh`.

## Configuration (.env)

Nexus is highly customizable. The `install.sh` script generates your `.env` file, but you can manually tune the AI models and defense systems:

| Variable | Default | Description |
|---|---|---|
| `INGESTION_SOURCE` | `webhook` | Source of data. Agents use `webhook`. `cloudwatch` is optional and needs AWS. |
| `WEIGHT_ISOLATION_FOREST` | 0.25 | Relative weight of the Isolation Forest model. |
| `WEIGHT_LSTM_AE` | 0.45 | Relative weight of the LSTM Autoencoder. |
| `WEIGHT_TRANSFORMER` | 0.30 | Relative weight of the Transformer Attention model. |
| `WEIGHT_VAE` | 0.30 | Relative weight of the Variational Autoencoder. |
| `CRITICAL_SCORE` | 0.85 | Threshold (0.0 - 1.0) required to trigger Active Defense. |
| `DEFENSE_MODE` | `dry_run` | `off`, `dry_run` (log only) or `enforce` (update firewall). |
| `DEFENSE_FIREWALL` | `auto` | `iptables`, `nftables` or `pfctl`. |
| `DEFENSE_BLOCK_SECONDS` | 300 | Quarantine duration for blocked IPs. |

## Active Defense Deep-Dive

When the system detects an attack:
1. **Safe Mode Activation:** Nexus returns `503 Service Unavailable` for non-essential APIs, protecting your backend while keeping the health and dashboard sockets alive.
2. **IP Quarantine:** The source IP of the malicious telemetry is immediately blocked at the OS level (`iptables`/`nftables`).
3. **Auto-Recovery:** Blocks expire automatically after `DEFENSE_BLOCK_SECONDS`. You can also manually unblock IPs via the Dashboard.

*Note: To use `enforce` mode in Docker, the container must be run with `--privileged` or `CAP_NET_ADMIN` to manipulate the host's firewall.*

## Prometheus & Monitoring

You can easily scrape Nexus using Prometheus. The `/metrics` endpoint is protected by basic auth.
```yaml
scrape_configs:
  - job_name: nexus
    basic_auth: { username: admin, password: <DASHBOARD_PASSWORD> }
    static_configs: [{ targets: ["nexus-host:80"] }]
```

## License
This project is licensed under the MIT License.
