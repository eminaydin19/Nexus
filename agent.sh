#!/bin/bash
NEXUS_URL="http://localhost/api/ingest"
NODE_ID=$(hostname)
echo "[*] Nexus Ajanı Başladı! Makine: $NODE_ID"
while true; do
  CPU=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
  MEM=$(free | awk '/Mem/{printf "%.2f", $3/$2 * 100.0}')
  TIME=$(date +%s)
  curl -s -X POST $NEXUS_URL -H "Content-Type: application/json" -d "{\"node_id\": \"$NODE_ID\", \"timestamp\": $TIME, \"cpu_pct\": $CPU, \"memory_pct\": $MEM, \"net_kbps\": 350.5, \"latency_ms\": 12.4}" > /dev/null
  sleep 2
done
