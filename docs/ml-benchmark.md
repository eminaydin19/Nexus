# ML ensemble compared with ECOD

We compared the four-model ensemble with [ECOD](https://arxiv.org/abs/2201.00382), a much simpler detector, and kept the ensemble. ECOD raised more false alarms and missed more incidents. It is far cheaper to run, so this is worth repeating on recorded data.

**The data is simulated, not recorded from production.** The result shows how the two compare on these patterns. It does not predict the false alarm rate on your servers.

Reproduce it from the repo root, after `scripts/test.sh` has built the image:

```bash
docker run --rm -v "$PWD":/app -w /app --entrypoint python nexus-test scripts/bench_ml.py
```

## Setup

- Three simulated servers (web, database, batch) sending a sample every 5 seconds.
- 14 days of training history, including one incident nobody flagged.
- 3 later days never seen in training, including a harmless deploy that moves the web server's memory baseline.
- 3 seeds, with 60 injected incidents per scenario on each seed.
- An incident counts as caught when at least a fifth of its points raise an alarm.

## Results

Each cell gives the range or mean across the 3 seeds.

| Measure | Ensemble | ECOD |
|---|---|---|
| False alarm rate, web | 0.00% | 11.9-15.8% |
| False alarm rate, database | 0.00-0.02% | 0.26-0.54% |
| False alarm rate, batch | 0.81-1.17% | 0.45-0.48% |
| False alarm points per server per day | 47-69 | 731-951 |
| Training CPU | 41-46 minutes | under 1 second |
| CPU per sample | 23 ms | under 0.1 ms |
| Peak memory while scoring | 350 MB | 61 MB |

ECOD's high web rate most likely comes from the harmless deploy, the one change only that server has. We did not rerun without it.

Share of incidents caught, at each model's own threshold:

| Incident | Ensemble | ECOD |
|---|---|---|
| CPU saturated for 30 minutes | 0.76 | 0.39 |
| Memory leak over 2 hours | 1.00 | 0.35 |
| Network traffic 20 times normal for 20 minutes | 0.82 | 0.46 |
| Latency 15 times normal for 15 minutes | 0.91 | 0.44 |
| CPU 15 points higher for 1 hour | 0.33 | 0.08 |
| Server gone quiet for 30 minutes | 1.00 | 1.00 |

## Known limits

- Even the ensemble raises about 50 false alarm points per server per day at this sample rate, mostly on the batch server. Slack only receives critical scores, with a cooldown, and a score never blocks anyone.
- Subtle incidents are mostly missed by both models.
- Scoring memory excludes the rest of central. Training memory was not measured.
