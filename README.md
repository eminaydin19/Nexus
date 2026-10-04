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

## 1-Click AWS Installation

Nexus comes with a fully automated setup script tailored for AWS EC2 (Ubuntu/Debian).

1. Connect to your AWS EC2 instance via SSH.
2. Clone this repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Nexus.git
   cd Nexus
   ```
3. Run the installer:
   ```bash
   ./install.sh
   ```

The script will automatically install Docker, prompt you for your AWS IAM keys (to fetch CloudWatch data), generate a secure `.env` configuration, and spin up the entire system.

## Configuration (.env)

Nexus is highly customizable. The `install.sh` script generates your `.env` file, but you can manually tune the AI models and defense systems:

| Variable | Default | Description |
|---|---|---|
| `INGESTION_SOURCE` | `cloudwatch` | Source of data. Set to `cloudwatch` for AWS production. |
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
