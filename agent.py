import argparse
import os
import socket
import time
import requests
import psutil

def get_net_kbps(interval: float = 1.0) -> float:
    net1 = psutil.net_io_counters()
    time.sleep(interval)
    net2 = psutil.net_io_counters()
    bytes_sent = net2.bytes_sent - net1.bytes_sent
    bytes_recv = net2.bytes_recv - net1.bytes_recv
    return (bytes_sent + bytes_recv) / 1024.0 / interval

def get_latency(url: str, session: requests.Session) -> float:
    try:
        start = time.time()
        session.get(url, timeout=2)
        return (time.time() - start) * 1000.0
    except requests.exceptions.RequestException:
        return 0.0

def main():
    parser = argparse.ArgumentParser(description="Nexus Cross-Platform Telemetry Agent")
    parser.add_argument("--url", type=str, default=os.environ.get("NEXUS_URL", "http://localhost:8000/api/ingest"), help="Target Nexus Ingest API URL")
    parser.add_argument("--node-id", type=str, default=os.environ.get("NEXUS_NODE_ID", socket.gethostname()), help="Node ID")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    parser.add_argument("--api-key", type=str, default=os.environ.get("NEXUS_API_KEY", ""), help="Nexus INGEST_API_KEY (or set NEXUS_API_KEY)")
    args = parser.parse_args()

    session = requests.Session()
    if args.api_key:
        session.headers["X-API-Key"] = args.api_key

    print(f"Starting Nexus Agent for node: {args.node_id}")
    print(f"Target URL: {args.url}")

    # Prepare latency check URL (e.g. /healthz instead of /api/ingest)
    base_url = args.url.rsplit("/api/ingest", 1)[0]
    health_url = f"{base_url}/healthz"

    # Initial call to cpu_percent to baseline it
    psutil.cpu_percent(interval=None)

    while True:
        loop_start = time.time()
        
        try:
            # Gather metrics
            cpu_pct = psutil.cpu_percent(interval=None)
            memory_pct = psutil.virtual_memory().percent
            net_kbps = get_net_kbps(interval=1.0)
            latency_ms = get_latency(health_url, session)

            payload = {
                "node_id": args.node_id,
                "timestamp": time.time(),
                "cpu_pct": cpu_pct,
                "memory_pct": memory_pct,
                "net_kbps": net_kbps,
                "latency_ms": latency_ms,
            }

            resp = session.post(args.url, json=payload, timeout=5)
            if resp.status_code == 200:
                print(f"[{time.strftime('%X')}] Sent telemetry: {payload}")
            else:
                print(f"[{time.strftime('%X')}] Failed to send telemetry: HTTP {resp.status_code} - {resp.text}")

        except Exception as e:
            print(f"[{time.strftime('%X')}] Error sending telemetry: {e}")

        elapsed = time.time() - loop_start
        sleep_time = max(0.0, args.interval - elapsed)
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
