import asyncio
import ipaddress
import logging
import os
import shutil
import sys
import time
from collections import deque
from collections.abc import Awaitable, Callable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from backend.metrics import counters

log = logging.getLogger("nexus.defense")

Runner = Callable[[list[str]], Awaitable[tuple[int, str]]]
EventSink = Callable[[dict], Awaitable[None]]

NFT_TABLE = "nexus"
PF_TABLE = "nexus_blocked"


async def run_command(argv: list[str]) -> tuple[int, str]:
    """Run a command without a shell. Returns (returncode, combined output)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
    except FileNotFoundError:
        return 127, f"{argv[0]}: command not found"
    except TimeoutError:
        return 124, f"{argv[0]}: timed out"
    return proc.returncode or 0, out.decode(errors="replace").strip()


def detect_firewall() -> str:
    if sys.platform == "darwin":
        return "pfctl"
    if shutil.which("nft"):
        return "nftables"
    return "iptables"


def parse_allowlist(entries: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.error("ignoring invalid allowlist entry %r", entry)
    return networks


def firewall_setup_commands(backend: str) -> list[list[str]]:
    """One-time idempotent commands needed before blocking (nftables only)."""
    if backend != "nftables":
        return []
    return [
        ["nft", "add", "table", "inet", NFT_TABLE],
        ["nft", "add", "set", "inet", NFT_TABLE, "blocked4", "{ type ipv4_addr; }"],
        ["nft", "add", "set", "inet", NFT_TABLE, "blocked6", "{ type ipv6_addr; }"],
        [
            "nft", "add", "chain", "inet", NFT_TABLE, "input",
            "{ type filter hook input priority -10; policy accept; }",
        ],
        ["nft", "add", "rule", "inet", NFT_TABLE, "input", "ip", "saddr", "@blocked4", "drop"],
        ["nft", "add", "rule", "inet", NFT_TABLE, "input", "ip6", "saddr", "@blocked6", "drop"],
    ]


def firewall_commands(backend: str, action: str, ip: str) -> list[list[str]]:
    """Build argv lists (never shell strings) for blocking/unblocking one validated IP."""
    address = ipaddress.ip_address(ip)
    v6 = address.version == 6
    if action not in ("block", "unblock"):
        raise ValueError(f"unknown action {action!r}")
    ip = str(address)
    if backend == "iptables":
        tool = "ip6tables" if v6 else "iptables"
        if action == "block":
            return [[tool, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]]
        return [[tool, "-D", "INPUT", "-s", ip, "-j", "DROP"]]
    if backend == "nftables":
        name = "blocked6" if v6 else "blocked4"
        verb = "add" if action == "block" else "delete"
        return [["nft", verb, "element", "inet", NFT_TABLE, name, f"{{ {ip} }}"]]
    if backend == "pfctl":
        verb = "add" if action == "block" else "delete"
        return [["pfctl", "-t", PF_TABLE, "-T", verb, ip]]
    raise ValueError(f"unknown firewall backend {backend!r}")


class ActiveDefender:
    """Reacts to critical anomalies: temporary Safe Mode plus optional quarantine of the offending IP.

    Modes: ``off`` does nothing, ``dry_run`` records what would happen, ``enforce`` runs firewall commands.
    """

    def __init__(
        self,
        critical_score: float = 0.85,
        mode: str = "dry_run",
        firewall: str = "auto",
        block_seconds: int = 300,
        safe_mode_seconds: int = 60,
        allowlist: list[str] | None = None,
        runner: Runner | None = None,
        clock: Callable[[], float] = time.time,
        on_event: EventSink | None = None,
    ):
        if mode not in ("off", "dry_run", "enforce"):
            raise ValueError(f"invalid defense mode {mode!r}")
        self.critical_score = critical_score
        self.mode = mode
        self.firewall = detect_firewall() if firewall == "auto" else firewall
        self.block_seconds = block_seconds
        self.safe_mode_seconds = safe_mode_seconds
        self._allow = parse_allowlist(allowlist if allowlist is not None else ["127.0.0.1", "::1"])
        self._run = runner or run_command
        self._clock = clock
        self.on_event = on_event

        self.safe_mode = False
        self.safe_mode_until = 0.0
        self.blocked: dict[str, dict] = {}
        self.events: deque[dict] = deque(maxlen=100)
        self._firewall_ready = False
        self._lock = asyncio.Lock()

        if mode == "enforce" and hasattr(os, "geteuid") and os.geteuid() != 0:
            log.warning("defense mode is 'enforce' but Nexus is not running as root; firewall commands will likely fail")

    # -- state ---------------------------------------------------------------------------------

    def is_safe_mode_active(self) -> bool:
        if self.safe_mode and self._clock() > self.safe_mode_until:
            self.safe_mode = False
            log.info("Safe Mode deactivated.")
        return self.safe_mode

    def is_protected(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            return True
        return any(address in network for network in self._allow if network.version == address.version)

    def status(self) -> dict:
        now = self._clock()
        return {
            "mode": self.mode,
            "firewall": self.firewall,
            "safe_mode": self.is_safe_mode_active(),
            "safe_mode_until": self.safe_mode_until if self.safe_mode else None,
            "block_seconds": self.block_seconds,
            "blocked": [
                {"ip": ip, "node": info["node"], "until": info["until"], "simulated": info["simulated"],
                 "remaining": max(0, round(info["until"] - now))}
                for ip, info in sorted(self.blocked.items())
            ],
        }

    # -- actions -------------------------------------------------------------------------------

    async def _emit(self, **event) -> dict:
        event = {"ts": self._clock(), "mode": self.mode, **event}
        self.events.appendleft(event)
        counters.inc("nexus_defense_actions_total", action=event["type"], mode=self.mode)
        if self.on_event:
            try:
                await self.on_event(event)
            except Exception:
                log.exception("defense event sink failed")
        return event

    async def _exec(self, commands: list[list[str]]) -> tuple[bool, str]:
        details = []
        for argv in commands:
            code, output = await self._run(argv)
            if code != 0:
                return False, f"{' '.join(argv)} -> exit {code}: {output}"[:300]
            details.append(" ".join(argv))
        return True, "; ".join(details)

    async def _ensure_firewall(self) -> None:
        if self._firewall_ready:
            return
        ok, detail = await self._exec(firewall_setup_commands(self.firewall))
        if ok:
            self._firewall_ready = True
        else:
            log.error("firewall setup failed: %s", detail)

    async def mitigate(self, node_id: str, anomaly_score: float, ip: str | None = None) -> None:
        if self.mode == "off" or anomaly_score < self.critical_score:
            return
        async with self._lock:
            await self._sweep_locked()
            await self._activate_safe_mode(node_id, anomaly_score)
            if ip:
                await self._block(node_id, ip, anomaly_score)

    async def _activate_safe_mode(self, node_id: str, score: float) -> None:
        was_active = self.is_safe_mode_active()
        self.safe_mode = True
        self.safe_mode_until = self._clock() + self.safe_mode_seconds
        if not was_active:
            log.warning("Safe Mode activated for %ss: critical anomaly on %s (score %.2f)",
                        self.safe_mode_seconds, node_id, score)
            await self._emit(type="safe_mode", node=node_id, ip=None, ok=True, score=score,
                             detail=f"non-essential API traffic rejected for {self.safe_mode_seconds}s")

    async def _block(self, node_id: str, ip: str, score: float) -> None:
        if ip in self.blocked:
            return
        if self.is_protected(ip):
            log.info("not blocking protected address %s (node %s)", ip, node_id)
            await self._emit(type="block_skipped", node=node_id, ip=ip, ok=True, score=score,
                             detail="address is loopback or allowlisted")
            return
        simulated = self.mode != "enforce"
        if simulated:
            ok, detail = True, f"would block {ip} via {self.firewall}"
        else:
            await self._ensure_firewall()
            ok, detail = await self._exec(firewall_commands(self.firewall, "block", ip))
        if ok:
            self.blocked[ip] = {"node": node_id, "until": self._clock() + self.block_seconds, "simulated": simulated}
            log.warning("%s %s (node %s, score %.2f) for %ss", "WOULD BLOCK" if simulated else "BLOCKED",
                        ip, node_id, score, self.block_seconds)
        else:
            log.error("block of %s failed: %s", ip, detail)
        await self._emit(type="block" if ok else "block_failed", node=node_id, ip=ip, ok=ok, score=score, detail=detail)

    async def unblock(self, ip: str, reason: str = "manual") -> bool:
        async with self._lock:
            return await self._unblock_locked(ip, reason)

    async def _unblock_locked(self, ip: str, reason: str) -> bool:
        info = self.blocked.get(ip)
        if info is None:
            return False
        if info["simulated"]:
            ok, detail = True, f"would unblock {ip}"
        else:
            ok, detail = await self._exec(firewall_commands(self.firewall, "unblock", ip))
        if ok:
            del self.blocked[ip]
        await self._emit(type="unblock" if ok else "unblock_failed", node=info["node"], ip=ip, ok=ok,
                         score=None, detail=f"{reason}: {detail}")
        return ok

    async def sweep_expired(self) -> None:
        async with self._lock:
            await self._sweep_locked()

    async def _sweep_locked(self) -> None:
        now = self._clock()
        for ip in [ip for ip, info in self.blocked.items() if info["until"] <= now]:
            await self._unblock_locked(ip, "expired")

    async def shutdown(self) -> None:
        """Lift every enforced block so a restart never leaves stale firewall rules behind."""
        async with self._lock:
            for ip in list(self.blocked):
                await self._unblock_locked(ip, "shutdown")


class SafeModeMiddleware:
    """While Safe Mode is active, rejects non-essential API traffic with 503."""

    ESSENTIAL = ("/healthz", "/api/health", "/api/ingest", "/api/defense", "/metrics", "/ws")

    def __init__(self, app: ASGIApp, defender: ActiveDefender):
        self.app = app
        self.defender = defender

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self.defender.is_safe_mode_active():
            path = scope["path"]
            if path.startswith("/api/") and not any(path == p or path.startswith(p + "/") for p in self.ESSENTIAL):
                response = JSONResponse(
                    {"detail": "Service Unavailable - Safe Mode Active"},
                    status_code=503,
                    headers={"Retry-After": str(max(1, int(self.defender.safe_mode_until - time.time())))},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
