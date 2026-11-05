# Tuning detection thresholds

The defaults are starting values. Real traffic should adjust them. Start in `observe` mode and read the Watch list in the panel before you enable `enforce`.

Set a value in `/etc/nexus-agent.env` on the server as `NEXUS_RULE_<FIELD>`, then run `systemctl restart nexus-agent`. An invalid value is logged and ignored, and the default stays in use. The window is 5 minutes, except for `port_scan`, which uses 60 seconds.

| Rule | Variable | Default | Reaction |
|---|---|---|---|
| `ssh_bruteforce` | `NEXUS_RULE_SSH_FAIL_THRESHOLD` | 10 failed logins | Block port, 1 hour |
| `web_login_bruteforce` | `NEXUS_RULE_WEB_LOGIN_THRESHOLD` | 30 `401`/`403` on login paths | Block port, 15 minutes |
| `web_probe` | `NEXUS_RULE_PROBE_THRESHOLD` | 10 listed paths with `4xx` | Block port, 30 minutes |
| `web_exploit` | `NEXUS_RULE_EXPLOIT_THRESHOLD` | 3 patterns across 5 URLs | Block port, 1 hour |
| `port_scan` | `NEXUS_RULE_SCAN_PORTS` | 20 closed ports | Alert alone; full block with log evidence, 15 minutes |
| `conn_flood` | `NEXUS_RULE_MAX_NEW_CONN_RATE` | 100 new connections/s in 2 samples | Rate limit, 10 minutes |
| `conn_flood` | `NEXUS_RULE_MAX_CONN_PER_IP` | 1000 open connections | Rate limit, 10 minutes |
| `distributed_flood` | `NEXUS_RULE_SYN_RECV_ALERT` | 500 SYN-RECV | Alert only |

Block durations use `NEXUS_RULE_TTL_<RULE>`, for example `NEXUS_RULE_TTL_WEB_PROBE=900`, in seconds. Values above 86400 are clamped to one day. Repeat offences double the duration up to that limit, except `conn_flood`, which does not grow.

Other lists: `NEXUS_RULE_LOGIN_PATHS`, `NEXUS_RULE_SSH_PORTS` and `NEXUS_RULE_WEB_PORTS`, each comma-separated.

## When to change what

- **A real customer appears in Watch or Blocks.** Mark the address as a customer in the panel first. Raise a threshold only if this repeats with different customers.
- **An office or reverse proxy hits `conn_flood`.** Raise `NEXUS_RULE_MAX_NEW_CONN_RATE`. A slowdown does not block the address, but its users can feel it.
- **An attack was missed.** Lower the matching threshold in small steps and watch in `observe` mode before you return to `enforce`. The project's top rule is that blocking a customer is worse than missing an attack.

The ML score never blocks anyone. `CRITICAL_SCORE` on central only decides when an anomaly alerts Slack.
