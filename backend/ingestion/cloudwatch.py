import asyncio
import logging
import time
from datetime import datetime, timezone

import boto3
from botocore.config import Config

from backend.schema import NodeSnapshot

log = logging.getLogger(__name__)

_DISCOVERY_TTL = 600.0
_MAX_QUERIES_PER_CALL = 500
_HINTS = {
    "cpu": "no AWS/EC2 CPUUtilization datapoints yet",
    "mem": "install the CloudWatch Agent (deploy/cloudwatch-agent.json)",
    "net": "no AWS/EC2 NetworkIn datapoints yet",
    "lat": "run deploy/latency_probe.sh on the instance",
}


class CloudWatchSource:
    name = "cloudwatch"

    def __init__(
        self,
        region: str,
        instance_ids: list[str],
        period: int,
        access_key: str = "",
        secret_key: str = "",
        memory_namespace: str = "CWAgent",
        memory_metric: str = "mem_used_percent",
        latency_namespace: str = "Nexus",
        latency_metric: str = "RequestLatency",
    ):
        session = boto3.Session(
            region_name=region,
            aws_access_key_id=access_key or None,
            aws_secret_access_key=secret_key or None,
        )
        config = Config(retries={"max_attempts": 5, "mode": "standard"}, connect_timeout=5, read_timeout=20)
        self._cw = session.client("cloudwatch", config=config)
        self._ec2 = session.client("ec2", config=config)
        self.period = period
        self.interval = float(period)
        self._ids = instance_ids
        self._memory = (memory_namespace, memory_metric)
        self._latency = (latency_namespace, latency_metric)
        self._discovered: list[str] = []
        self._discovered_at = 0.0
        self._last_ts: dict[str, float] = {}
        self._warned: set[tuple[str, tuple[str, ...]]] = set()

    def _instances(self) -> list[str]:
        if self._ids:
            return self._ids
        if time.monotonic() - self._discovered_at > _DISCOVERY_TTL:
            found: list[str] = []
            pages = self._ec2.get_paginator("describe_instances").paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )
            for page in pages:
                for reservation in page["Reservations"]:
                    found.extend(i["InstanceId"] for i in reservation["Instances"])
            self._discovered = sorted(found)
            self._discovered_at = time.monotonic()
            log.info("discovered %d running instances", len(found))
        return self._discovered

    def _query(self, key: str, idx: int, instance_id: str, namespace: str, metric: str, stat: str) -> dict:
        return {
            "Id": f"{key}{idx}",
            "MetricStat": {
                "Metric": {
                    "Namespace": namespace,
                    "MetricName": metric,
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                },
                "Period": self.period,
                "Stat": stat,
            },
            "ReturnData": True,
        }

    def _latest(self, queries: list[dict], start: datetime, end: datetime) -> dict[str, tuple[float, float]]:
        latest: dict[str, tuple[float, float]] = {}
        for offset in range(0, len(queries), _MAX_QUERIES_PER_CALL):
            chunk = queries[offset : offset + _MAX_QUERIES_PER_CALL]
            pages = self._cw.get_paginator("get_metric_data").paginate(
                MetricDataQueries=chunk,
                StartTime=start,
                EndTime=end,
                ScanBy="TimestampDescending",
            )
            for page in pages:
                for result in page["MetricDataResults"]:
                    if result["Values"] and result["Id"] not in latest:
                        latest[result["Id"]] = (result["Timestamps"][0].timestamp(), float(result["Values"][0]))
        return latest

    def _collect(self) -> list[NodeSnapshot]:
        ids = self._instances()
        if not ids:
            log.warning("no EC2 instances to monitor")
            return []

        queries: list[dict] = []
        for idx, iid in enumerate(ids):
            queries.append(self._query("cpu", idx, iid, "AWS/EC2", "CPUUtilization", "Average"))
            queries.append(self._query("net", idx, iid, "AWS/EC2", "NetworkIn", "Sum"))
            queries.append(self._query("mem", idx, iid, *self._memory, "Average"))
            queries.append(self._query("lat", idx, iid, *self._latency, "Average"))

        now = time.time()
        end_epoch = int(now // self.period) * self.period
        lookback = max(self.period * 4, 900)
        start_epoch = end_epoch - (lookback // self.period + 1) * self.period
        latest = self._latest(
            queries,
            datetime.fromtimestamp(start_epoch, tz=timezone.utc),
            datetime.fromtimestamp(end_epoch, tz=timezone.utc),
        )

        snapshots: list[NodeSnapshot] = []
        for idx, iid in enumerate(ids):
            got = {key: latest.get(f"{key}{idx}") for key in ("cpu", "mem", "net", "lat")}
            missing = tuple(key for key, value in got.items() if value is None)
            if missing:
                marker = (iid, missing)
                if marker not in self._warned:
                    self._warned.add(marker)
                    log.warning(
                        "%s skipped, missing: %s",
                        iid,
                        "; ".join(f"{key} ({_HINTS[key]})" for key in missing),
                    )
                continue
            self._warned = {w for w in self._warned if w[0] != iid}
            timestamp = got["cpu"][0]
            if timestamp <= self._last_ts.get(iid, 0.0):
                continue
            self._last_ts[iid] = timestamp
            snapshots.append(
                NodeSnapshot(
                    node_id=iid,
                    timestamp=timestamp,
                    cpu_pct=round(got["cpu"][1], 3),
                    memory_pct=round(got["mem"][1], 3),
                    net_kbps=round(got["net"][1] / self.period / 1024.0, 3),
                    latency_ms=round(got["lat"][1], 3),
                )
            )
        return snapshots

    async def poll(self) -> list[NodeSnapshot]:
        return await asyncio.to_thread(self._collect)
