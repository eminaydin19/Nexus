#!/usr/bin/env bash
set -euo pipefail

url="${1:?usage: latency_probe.sh <url> [interval-seconds]}"
interval="${2:-60}"
imds=http://169.254.169.254/latest
imds_token="$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "$imds/api/token")"
instance_id="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" "$imds/meta-data/instance-id")"

while true; do
    if seconds="$(curl -fsS -o /dev/null -m 10 -w '%{time_total}' "$url")"; then
        aws cloudwatch put-metric-data --namespace Nexus --metric-name RequestLatency \
            --dimensions "InstanceId=$instance_id" --unit Milliseconds \
            --value "$(awk -v s="$seconds" 'BEGIN { print s * 1000 }')"
    fi
    sleep "$interval"
done
