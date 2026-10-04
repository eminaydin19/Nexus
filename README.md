# Nexus

Nexus is a real-time anomaly detection system for cloud infrastructure. It continuously analyzes host metrics (CPU, memory, network I/O, and latency) to identify operational irregularities, degrading performance, and systemic failures before they escalate into critical incidents.

## Architecture

Traditional alerting relies on static thresholds, which often fail to capture complex, non-linear relationships in system behavior, leading to alert fatigue or undetected outages. Nexus addresses this by applying a multi-model ensemble approach:

- **Isolation Forest:** Rapidly identifies statistical outliers in multidimensional space.
- **LSTM Autoencoders:** Captures sequential dependencies to detect temporal anomalies.
- **Variational Autoencoders (VAE):** Models the latent distribution of healthy states to flag structural deviations.

By aggregating anomaly scores from these models, Nexus provides a unified "Ensemble Score," which balances precision and recall, dramatically reducing false positives in production environments.

## Deployment

The system is optimized for edge and low-resource environments, utilizing a CPU-bound inference pipeline that prevents out-of-memory errors on small virtual machines. 

### Prerequisites
- Docker
- Docker Compose
- Python 3.10+ (for the native host probe)

### Getting Started

1. **Environment Setup**
   Clone the repository and prepare the configuration:
   ```bash
   git clone https://github.com/eminaydin19/Nexus.git
   cd Nexus
   cp .env.example .env
   ```
   *Note: Ensure `INGESTION_SOURCE=webhook` is set in your `.env` file.*

2. **Start the Nexus Services**
   Bring up the backend, models, and real-time dashboard:
   ```bash
   docker compose up -d --build
   ```
   The dashboard is exposed by default on port `80` via a Caddy reverse proxy.

3. **Deploy the Metric Probe**
   To stream actual system telemetry into Nexus, deploy the native Python probe on your target instances. 
   ```bash
   pip install psutil
   INTERVAL=5 NODE_ID=$(hostname) API_URL=http://<YOUR_NEXUS_HOST>/api/ingest nohup python3 deploy/probe.py > probe.log 2>&1 &
   ```

## Configuration

Nexus behavior, including model sensitivity and alerting thresholds, can be adjusted dynamically via the `.env` file. A service restart is required to apply changes.

| Variable | Default | Description |
|---|---|---|
| `WEIGHT_ISOLATION_FOREST` | 0.25 | Relative weight of the Isolation Forest model |
| `WEIGHT_LSTM_AE` | 0.45 | Relative weight of the LSTM Autoencoder |
| `WEIGHT_VAE` | 0.30 | Relative weight of the Variational Autoencoder |
| `CRITICAL_SCORE` | 0.85 | Threshold (0.0 - 1.0) required to trigger an alert |
| `SLACK_WEBHOOK_URL` | | (Optional) Webhook URL for incident notification |

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
