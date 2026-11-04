from __future__ import annotations

import glob
import json
import logging
import os
import re
import socket
import struct
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Mapping, Optional, Tuple

from .enforcer import MODES
from .parsers import normalize_ip
from .rules import RuleConfig

log = logging.getLogger("nexus_agent.config")

STATE_FILE = "state.json"
_SSHD_PORT = re.compile(r"\s*port\s+(\d+)\s*(?:#.*)?$", re.I)
_SSHD_INCLUDE = re.compile(r"\s*include\s+(.+)$", re.I)


def _csv(raw: Optional[str]) -> Tuple[str, ...]:
    return tuple(x.strip() for x in (raw or "").split(",") if x.strip())


def _ports(name: str, raw: Optional[str]) -> Tuple[int, ...]:
    out = []
    for item in _csv(raw):
        if item.isdigit() and 0 < int(item) < 65536:
            out.append(int(item))
        else:
            log.warning("ignoring invalid %s entry: %r", name, item)
    return tuple(out)


def _sshd_ports(path: str, seen: Optional[set] = None) -> Tuple[int, ...]:
    seen = set() if seen is None else seen
    real = os.path.realpath(path)
    if real in seen:
        return ()
    seen.add(real)
    ports = []  # type: List[int]
    try:
        with open(path, errors="replace") as f:
            for line in f:
                m = _SSHD_PORT.match(line)
                if m and 0 < int(m.group(1)) < 65536:
                    ports.append(int(m.group(1)))
                inc = _SSHD_INCLUDE.match(line.split("#", 1)[0].rstrip())
                for pattern in inc.group(1).split() if inc else ():
                    # sshd resolves relative includes against /etc/ssh, the main config's directory.
                    pattern = os.path.join(os.path.dirname(real), pattern.strip(chr(34)))
                    for found in sorted(glob.glob(pattern)):
                        ports.extend(_sshd_ports(found, seen))
    except OSError:
        pass
    return tuple(ports)


@dataclass
class AgentConfig:
    url: str
    key: str = field(repr=False)
    node_id: Optional[str]
    max_mode: str
    web_logs: Tuple[str, ...]
    state_dir: Path
    allowlist: Tuple[str, ...]
    allow_insecure: bool
    rules: RuleConfig

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, sshd_config: str = "/etc/ssh/sshd_config") -> "AgentConfig":
        env = os.environ if env is None else env
        url, key = env.get("NEXUS_URL", "").strip(), env.get("NEXUS_API_KEY", "").strip()
        if not url or not key:
            raise ValueError("NEXUS_URL and NEXUS_API_KEY must be set")
        max_mode = env.get("NEXUS_MAX_MODE", "enforce").strip()
        if max_mode not in MODES:
            # A typo in the local safety limit must not silently leave enforce allowed.
            raise ValueError("NEXUS_MAX_MODE must be one of %s" % ", ".join(MODES))
        rules = RuleConfig.from_env(env)
        rules.ssh_ports = tuple(sorted(set(_ports("NEXUS_SSH_PORTS", env.get("NEXUS_SSH_PORTS")) or rules.ssh_ports)
                                       | set(_sshd_ports(sshd_config))))
        rules.web_ports = _ports("NEXUS_WEB_PORTS", env.get("NEXUS_WEB_PORTS")) or rules.web_ports
        return cls(
            url=url,
            key=key,
            node_id=env.get("NEXUS_NODE_ID"),
            max_mode=max_mode,
            web_logs=_csv(env.get("NEXUS_WEB_LOGS")),
            state_dir=Path(env.get("NEXUS_STATE_DIR", "/var/lib/nexus-agent")),
            allowlist=_csv(env.get("NEXUS_ALLOWLIST")),
            allow_insecure=is_insecure(env),
            rules=rules,
        )


def is_insecure(env: Mapping[str, str]) -> bool:
    return env.get("NEXUS_INSECURE", "").strip().lower() in ("1", "true", "yes")


def read_gateways(path: str = "/proc/net/route") -> List[str]:
    out = []
    try:
        with open(path) as f:
            for line in f:
                cols = line.split()
                if len(cols) < 4 or cols[1] != "00000000":
                    continue
                try:
                    if int(cols[3], 16) & 2:  # RTF_GATEWAY
                        out.append(socket.inet_ntoa(struct.pack("<L", int(cols[2], 16))))
                except (ValueError, struct.error):
                    continue
    except OSError:
        pass
    return out


def read_resolvers(path: str = "/etc/resolv.conf") -> List[str]:
    out = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                cols = line.split()
                if len(cols) >= 2 and cols[0] == "nameserver":
                    out.append(cols[1])
    except OSError:
        pass
    return out


def resolve_host(host: Optional[str], timeout: float = 2.0, getaddrinfo=socket.getaddrinfo) -> List[str]:
    if not host:
        return []
    found: List[str] = []

    def work():
        try:
            ips = {normalize_ip(info[4][0]) for info in getaddrinfo(host, None)}
            found.extend(i for i in ips if i)
        except Exception as exc:
            log.warning("cannot resolve central host: %s", exc)

    # A daemon thread, because getaddrinfo has no timeout and a pool would hold process exit on a hung lookup.
    t = threading.Thread(target=work, daemon=True, name="nexus-resolve")
    t.start()
    t.join(timeout)
    if t.is_alive():
        log.warning("resolving central host timed out")
        return []
    return found


def load_state(state_dir) -> Optional[Tuple[str, List[str]]]:
    try:
        data = json.loads((Path(state_dir) / STATE_FILE).read_text())
    except OSError:
        return None
    except ValueError:
        log.warning("corrupt state file in %s; using defaults", state_dir)
        return None
    if not isinstance(data, dict):
        return None
    mode, allow = data.get("mode"), data.get("allowlist")
    if mode not in MODES or not isinstance(allow, list) or not all(isinstance(i, str) for i in allow):
        log.warning("invalid state file in %s; using defaults", state_dir)
        return None
    return mode, allow


def load_ssh_ok(state_dir) -> list:
    try:
        items = json.loads((Path(state_dir) / STATE_FILE).read_text()).get("ssh_ok")
    except (OSError, ValueError, AttributeError):
        return []
    return items if isinstance(items, list) else []


def save_state(state_dir, mode: str, allowlist: List[str], ssh_ok: Optional[list] = None) -> bool:
    tmp = None
    try:
        directory = Path(state_dir)
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".state-")
        with os.fdopen(fd, "w") as f:
            json.dump({"mode": mode, "allowlist": allowlist, "ssh_ok": ssh_ok or []}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(directory / STATE_FILE))
        return True
    except OSError as exc:
        log.error("cannot write state file: %s", exc)
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return False
