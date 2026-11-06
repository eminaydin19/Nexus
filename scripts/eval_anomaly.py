"""Compare fail2ban, rules, model and rules + model on data the model and its thresholds never saw.

docker run --rm -v "$PWD":/app -w /app --entrypoint python nexus-test scripts/eval_anomaly.py
docker run --rm -v "$PWD":/app -w /app --entrypoint python nexus-test scripts/eval_anomaly.py --real events.jsonl
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexus_agent.anomaly import load_models  # noqa: E402
from scripts.replay import SYSTEMS, blocked, replay  # noqa: E402
from training.anomaly_sim import simulate  # noqa: E402

REPORT_SEEDS = (400, 401, 402, 403, 404)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def wilson(hits: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    if total == 0:
        return (0.0, 1.0)
    p = hits / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def pct(hits: int, total: int) -> str:
    if total == 0:
        return "no data"
    low, high = wilson(hits, total)
    return "%.1f%% (%d/%d, CI %.1f-%.1f)" % (100 * hits / total, hits, total, 100 * low, 100 * high)


def score(labels: Dict[str, str], first_seen: Dict[str, float], lines, models, **jail) -> dict:
    """Per system: which labeled addresses got blocked. Unlabeled ("unclear") addresses are counted apart."""
    out = {}
    for system in SYSTEMS:
        hit = blocked(replay(lines, system, models, **jail))
        by_label = defaultdict(lambda: [0, 0])
        delays = []
        for ip, label in labels.items():
            by_label[label][1] += 1
            if ip in hit:
                by_label[label][0] += 1
                if label.startswith("attack"):
                    delays.append(hit[ip] - first_seen[ip])
        out[system] = {"labels": {k: list(v) for k, v in by_label.items()}, "blocked": hit, "delays": sorted(delays)}
    return out


def merge(total: dict, part: dict) -> None:
    for system, result in part.items():
        into = total.setdefault(system, {"labels": defaultdict(lambda: [0, 0]), "delays": []})
        for label, (hits, count) in result["labels"].items():
            into["labels"][label][0] += hits
            into["labels"][label][1] += count
        into["delays"] += result["delays"]


def table(total: dict) -> str:
    rows = ["| Measure | " + " | ".join(SYSTEMS) + " |", "|---|" + "---|" * len(SYSTEMS)]
    labels = sorted({label for r in total.values() for label in r["labels"]})
    for label in labels:
        rows.append("| %s | %s |" % (label, " | ".join(pct(*total[s]["labels"].get(label, [0, 0])) for s in SYSTEMS)))
    for name, wanted in (("Recall, all attacks", True), ("Share of customers blocked", False)):
        cells = []
        for system in SYSTEMS:
            pairs = [v for k, v in total[system]["labels"].items() if k.startswith("attack") == wanted and k != "unclear"]
            cells.append(pct(sum(p[0] for p in pairs), sum(p[1] for p in pairs)))
        rows.append("| **%s** | %s |" % (name, " | ".join(cells)))
    cells = []
    for system in SYSTEMS:
        labels_of = total[system]["labels"]
        attacks = sum(v[0] for k, v in labels_of.items() if k.startswith("attack"))
        wrong = sum(v[0] for k, v in labels_of.items() if not k.startswith("attack") and k != "unclear")
        cells.append(pct(attacks, attacks + wrong))
    rows.append("| **Block precision** | %s |" % " | ".join(cells))
    cells = []
    for system in SYSTEMS:
        delays = sorted(total[system]["delays"])
        cells.append("%.0f s" % delays[len(delays) // 2] if delays else "no data")
    rows.append("| Median time to block | %s |" % " | ".join(cells))
    return "\n".join(rows)


def simulated(models) -> None:
    total = {}
    gained = attackers = 0
    for seed in REPORT_SEEDS:
        records = simulate(seed)
        labels, first = {}, {}
        for ts, _source, _line, label, ip in records:
            labels[ip] = label
            first.setdefault(ip, ts)
        result = score(labels, first, [(r[0], r[1], r[2]) for r in records], models)
        merge(total, result)
        extra = set(result["hybrid"]["blocked"]) - set(result["rules"]["blocked"])
        gained += sum(labels[ip].startswith("attack") for ip in extra)
        attackers += sum(label.startswith("attack") for label in labels.values())
    print(table(total))
    print()
    print("Attackers blocked only with the model:", gained, "of", attackers)


def _ssh_line(row: dict, synthetic: str) -> str:
    t = time.gmtime(row["t"])
    head = "%s %2d %02d:%02d:%02d host sshd[1]: " % (_MONTHS[t.tm_mon - 1], t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
    user, port = row["user"], row["port"]
    return head + {
        "invalid": "Invalid user %s from %s port %d" % (user, synthetic, port),
        "closed": "Connection closed by authenticating user %s %s port %d [preauth]" % (user, synthetic, port),
        "failed": "Failed password for %s from %s port %d ssh2" % (user, synthetic, port),
        "ok": "Accepted publickey for %s from %s port %d ssh2" % (user, synthetic, port),
    }[row["kind"]]


def _web_line(row: dict, synthetic: str) -> str:
    t = time.gmtime(row["t"])
    # The real query text never left the server, only that a known pattern matched. This one matches the same way.
    path = row["path"] + ("?id=1+UNION+SELECT+2" if row["exploit"] else "")
    return '%s - - [%02d/%s/%d:%02d:%02d:%02d +0000] "%s %s HTTP/1.1" %d 1 "-" "%s"' % (
        synthetic, t.tm_mday, _MONTHS[t.tm_mon - 1], t.tm_year, t.tm_hour, t.tm_min, t.tm_sec, row["method"], path,
        row["status"], row["ua"])


def real(path: Path, models) -> None:
    rows = [json.loads(line) for line in path.open()]
    events = sorted((r for r in rows if r["src"] in ("ssh", "web")), key=lambda r: r["t"])
    jail = next((r["jail"] for r in rows if r["src"] == "meta"), {})
    bans = {r["ip"] for r in rows if r["src"] == "ban"}
    synthetic = {}  # type: Dict[str, int]

    def fake(ip: str) -> str:
        n = synthetic.setdefault(ip, len(synthetic) + 1)
        return "11.%d.%d.%d" % ((n >> 16) & 255, (n >> 8) & 255, n & 255)

    ok, invalid, seen, assets, probes = set(), defaultdict(int), set(), set(), defaultdict(int)
    for r in events:
        if r["src"] == "ssh":
            seen.add(("ssh", r["ip"]))
            if r["kind"] == "ok":
                ok.add(r["ip"])
            elif r["kind"] == "invalid":
                invalid[r["ip"]] += 1
        else:
            seen.add(("web", r["ip"]))
            if r["path"].startswith("/p/") and not r["exploit"]:
                if "." in r["path"]:
                    assets.add(r["ip"])
            else:
                probes[r["ip"]] += 1

    labels, first = {}, {}
    lines = []  # type: List[Tuple[float, str, str]]
    for r in events:
        ip = fake(r["ip"])
        first.setdefault(ip, r["t"])
        lines.append((r["t"], r["src"], (_ssh_line if r["src"] == "ssh" else _web_line)(r, ip)))
    for channel, ip in seen:
        name = fake(ip)
        if ip in ok:
            labels[name] = "customer_ssh_login"
        elif channel == "ssh":
            labels.setdefault(name, "attack_ssh_real" if invalid[ip] >= 2 else "unclear")
        elif probes[ip] and ip not in assets:
            labels.setdefault(name, "attack_web_real")
        elif not probes[ip]:
            labels.setdefault(name, "customer_web_real")
        else:
            labels.setdefault(name, "unclear")

    def number(name: str, default: float) -> float:
        try:
            return float(jail.get(name, default))
        except ValueError:
            return default

    settings = {"maxretry": int(number("maxretry", 5)), "findtime": number("findtime", 600), "bantime": number("bantime", 600)}
    result = score(labels, first, lines, models, **settings)
    total = {}
    merge(total, result)
    print(table(total))
    print()
    print("Addresses:", len(labels), "jail:", settings, "actual fail2ban bans in its logs:", len(bans))
    hybrid = set(result["hybrid"]["blocked"])
    reversed_ids = {fake(ip): ip for _, ip in seen}
    actual = {reversed_ids[n] for n in hybrid if n in reversed_ids}
    print("Actually banned by fail2ban and also blocked by rules + model:", len(actual & bans), "of", len(bans))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--real", type=Path)
    args = parser.parse_args()
    models = load_models()
    if not models:
        sys.exit("no model")
    if args.real:
        real(args.real, models)
    else:
        simulated(models)


if __name__ == "__main__":
    main()
