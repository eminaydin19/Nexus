# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/eminaydin19/Nexus/security/advisories/new) on GitHub. Do not file a public issue for a vulnerability. Include the affected commit, the steps to reproduce, and the impact you observed.

There is no paid bounty and no guaranteed response time. This is a project maintained by one person.

## What an agent can do

The agent runs as the unprivileged `nexus-agent` user under systemd, with two capabilities. `CAP_NET_ADMIN` lets it manage the nftables table `inet nexus`. `CAP_DAC_READ_SEARCH` lets it read logs, and it also allows reading any file on the server, so treat a compromised agent as able to read secrets. The agent connects out to central and opens no port.

## If central is compromised

Central can send an agent only these commands: unblock an IP, replace the allowlist, change the mode. An attacker who controls central can therefore:

- Lift blocks and add addresses to the allowlist, which weakens protection.
- Switch agents to `enforce` or to `off`, unless `NEXUS_MAX_MODE=observe` in `/etc/nexus-agent.env` limits that server. Central cannot change that file.
- Read everything agents reported, including log lines kept as evidence and client IP addresses.

Central cannot run commands on a server, write files there, update the agent, or tell an agent to block an address. Blocks come only from the agent's own log evidence. The per-IP anomaly model ships inside the agent package, so central cannot change it either.

## Hardening a deployment

- Serve central over HTTPS. Use `./install.sh --domain` or an SSH tunnel. `NEXUS_INSECURE` is for testing only: it disables certificate checks between agent and central.
- Enable `TRUST_PROXY_HEADERS` only behind a proxy you control, such as the bundled Caddy.
- Keep `.env` at mode 600. It holds the dashboard password.
- Enrollment tokens work once. Create them when you need them.
