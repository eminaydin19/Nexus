from __future__ import annotations

import logging
import os
import queue
import subprocess
import threading
import time
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

import psutil

from .parsers import MAX_LINE, normalize_ip

log = logging.getLogger("nexus_agent.collectors")

MAX_READ = 4 * 1024 * 1024
RECHECK_SECONDS = 60
POLL_SECONDS = 1
MAX_NET_KBPS = 1e9

SSH_LOGS = ("/var/log/auth.log", "/var/log/secure")
WEB_LOGS = ("/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log")
KERN_LOG = "/var/log/kern.log"
# short-iso, not cat: the ssh parser anchors on the "sshd[pid]:" header that -o cat removes.
SSH_JOURNAL = ("-u", "ssh", "-u", "sshd", "-n", "0", "-f", "-o", "short-iso")
KERNEL_JOURNAL = ("-k", "-n", "0", "-f", "-o", "short-iso")


class FileTail:
    def __init__(self, path, recheck: float = RECHECK_SECONDS, clock: Callable[[], float] = time.monotonic,
                 from_start: bool = False):
        self.path = str(path)
        self._recheck, self._clock = recheck, clock
        self._f = None
        self._id = None  # type: Optional[Tuple[int, int]]
        self._buf = b""
        self._skip = False
        self._next = 0.0
        self._noted = False
        self._open(at_end=not from_start)

    def _open(self, at_end: bool) -> None:
        try:
            f = open(self.path, "rb", buffering=0)
        except OSError as exc:
            if not self._noted:
                log.info("log %s unavailable (%s); rechecking every %ds", self.path, exc.strerror, self._recheck)
                self._noted = True
            self._next = self._clock() + self._recheck
            return
        st = os.fstat(f.fileno())
        if at_end:
            f.seek(0, os.SEEK_END)
        self._f, self._id, self._buf, self._skip = f, (st.st_dev, st.st_ino), b"", False
        if self._noted:
            log.info("log %s is now available", self.path)
            self._noted = False

    def read_lines(self) -> List[str]:
        if self._f is None:
            if self._clock() < self._next:
                return []
            self._open(at_end=False)
            if self._f is None:
                return []
        try:
            st = os.stat(self.path)
        except OSError:
            st = None
        rotated = st is not None and (st.st_dev, st.st_ino) != self._id
        if st is not None and not rotated and st.st_size < self._f.tell():  # copytruncate
            self._f.seek(0)
            self._buf, self._skip = b"", False
        chunk = self._f.read(MAX_READ) or b""
        lines = self._split(chunk)
        if rotated and len(chunk) < MAX_READ:
            if self._buf and not self._skip:
                lines.append(self._buf.decode("utf-8", "replace"))
            self._f.close()
            self._f = None
            self._open(at_end=False)
            if self._f is not None:
                lines += self._split(self._f.read(MAX_READ) or b"")
        return lines

    def _split(self, chunk: bytes) -> List[str]:
        parts = (self._buf + chunk).split(b"\n")
        self._buf = parts.pop()
        out = []
        for raw in parts:
            # The end of an over-long line is attacker-shaped text that must not parse as a line of its own.
            if self._skip:
                self._skip = False
            elif len(raw) <= MAX_LINE:
                out.append(raw.decode("utf-8", "replace"))
        if len(self._buf) > MAX_LINE:
            self._buf, self._skip = b"", True
        return out


class JournalTail:
    def __init__(self, args: Sequence[str], binary: str = "journalctl", backoff: float = 1.0, max_backoff: float = 60.0):
        self._argv = [binary] + list(args)
        self._backoff, self._max_backoff = backoff, max_backoff
        self._proc = None  # type: Optional[subprocess.Popen]

    def terminate(self) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()

    def run(self, sink: Callable[[str], None], stop: threading.Event) -> None:
        delay = self._backoff
        while not stop.is_set():
            started = time.monotonic()
            try:
                self._proc = subprocess.Popen(self._argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            except OSError as exc:
                log.warning("cannot start %s: %s", self._argv[0], exc)
            else:
                self._pump(self._proc, sink)
                rc = self._proc.wait()
                if not stop.is_set():
                    log.warning("%s exited with %s; restarting", self._argv[0], rc)
            if time.monotonic() - started >= self._max_backoff:
                delay = self._backoff
            if stop.wait(delay):
                return
            delay = min(delay * 2, self._max_backoff)

    @staticmethod
    def _pump(proc: subprocess.Popen, sink: Callable[[str], None]) -> None:
        skip = False
        with proc.stdout as out:
            while True:
                raw = out.readline(MAX_LINE + 1)
                if not raw:
                    return
                complete = raw.endswith(b"\n")
                if complete and not skip:
                    sink(raw.decode("utf-8", "replace"))
                skip = not complete


class LineQueue:
    def __init__(self, maxsize: int = 20000):
        self._q = queue.Queue(maxsize)  # type: queue.Queue
        self.dropped = 0

    def put(self, source: str, line: str) -> None:
        try:
            self._q.put_nowait((source, line))
        except queue.Full:
            self.dropped += 1

    def drain(self, limit: int) -> Iterator[Tuple[str, str]]:
        for _ in range(limit):
            try:
                yield self._q.get_nowait()
            except queue.Empty:
                return


class LogCollectors:
    """Per source, exactly one reader: a file and a journal for the same source would double count failed logins."""

    def __init__(self, lines: LineQueue, ssh_logs: Iterable = SSH_LOGS, web_logs: Iterable = WEB_LOGS,
                 kern_log=KERN_LOG, journalctl: Optional[str] = None, clock: Callable[[], float] = time.monotonic):
        self._lines, self._clock = lines, clock
        self.files = []  # type: List[Tuple[str, FileTail]]
        self.journals = []  # type: List[Tuple[str, JournalTail]]
        self._pending_ssh = []  # type: List[str]
        self._next_ssh = clock() + RECHECK_SECONDS

        ssh_logs = [str(p) for p in ssh_logs]
        present = [p for p in ssh_logs if os.path.exists(p)]
        if present:
            self.files.append(("ssh", FileTail(present[0], clock=clock)))
        elif journalctl:
            self.journals.append(("ssh", JournalTail(SSH_JOURNAL, binary=journalctl)))
        elif ssh_logs:
            log.info("no ssh log found (%s); rechecking every %ds", ", ".join(ssh_logs), RECHECK_SECONDS)
            self._pending_ssh = ssh_logs

        for path in {os.path.realpath(str(p)): str(p) for p in web_logs}.values():
            self.files.append(("web", FileTail(path, clock=clock)))

        if journalctl:
            self.journals.append(("scan", JournalTail(KERNEL_JOURNAL, binary=journalctl)))
        else:
            self.files.append(("scan", FileTail(kern_log, clock=clock)))

    def poll_files(self) -> None:
        if self._pending_ssh and self._clock() >= self._next_ssh:
            self._next_ssh = self._clock() + RECHECK_SECONDS
            present = [p for p in self._pending_ssh if os.path.exists(p)]
            if present:
                self.files.append(("ssh", FileTail(present[0], clock=self._clock, from_start=True)))
                self._pending_ssh = []
        for source, tail in self.files:
            try:
                for line in tail.read_lines():
                    self._lines.put(source, line)
            except Exception:
                log.exception("reading %s failed", tail.path)

    def _poll_loop(self, stop: threading.Event) -> None:
        while not stop.wait(POLL_SECONDS):
            self.poll_files()

    def start(self, stop: threading.Event) -> None:
        threading.Thread(target=self._poll_loop, args=(stop,), daemon=True, name="nexus-files").start()
        for source, tail in self.journals:
            sink = (lambda s: lambda line: self._lines.put(s, line))(source)
            threading.Thread(target=tail.run, args=(sink, stop), daemon=True, name="nexus-journal-" + source).start()

    def terminate(self) -> None:
        for _, tail in self.journals:
            tail.terminate()


_last_net = None  # type: Optional[Tuple[float, int]]
_denied_logged = False


def sample_metrics() -> Dict[str, float]:
    global _last_net
    counters = psutil.net_io_counters()
    kbps = 0.0
    if counters is not None:
        now, total = time.monotonic(), counters.bytes_sent + counters.bytes_recv
        if _last_net is not None and now > _last_net[0]:
            kbps = min(max(0.0, (total - _last_net[1]) / 1024.0 / (now - _last_net[0])), MAX_NET_KBPS)
        _last_net = (now, total)
    return {
        "cpu_pct": min(max(float(psutil.cpu_percent(interval=None)), 0.0), 100.0),
        "memory_pct": min(max(float(psutil.virtual_memory().percent), 0.0), 100.0),
        "net_kbps": float(kbps),
    }


def read_connections() -> list:
    global _denied_logged
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError) as exc:
        if not _denied_logged:
            log.warning("connection table access denied (%s); connection rules are idle", type(exc).__name__)
            _denied_logged = True
        return []
    _denied_logged = False
    return conns


def sample_connections(ssh_ports: Iterable[int] = (22,), conns: Optional[list] = None
                       ) -> Tuple[Dict[str, int], int, Set[str], Set[int]]:
    conns = read_connections() if conns is None else conns
    ssh_ports = set(ssh_ports)
    listening = {c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN and c.laddr and 0 < c.laddr.port < 65536}
    per_ip = {}  # type: Dict[str, int]
    syn_recv = 0
    active_ssh = set()  # type: Set[str]
    for c in conns:
        if c.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_RECV) or not c.raddr or not c.laddr:
            continue
        if c.status == psutil.CONN_SYN_RECV:
            syn_recv += 1
        ip = normalize_ip(c.raddr.ip)
        if ip is None:
            continue
        # A local port we do not listen on means we dialled out; that peer is not flooding us.
        if c.laddr.port in listening:
            per_ip[ip] = per_ip.get(ip, 0) + 1
        if c.status == psutil.CONN_ESTABLISHED and c.laddr.port in ssh_ports:
            active_ssh.add(ip)
    return per_ip, syn_recv, active_ssh, listening


def web_peers(web_ports: Iterable[int], conns: Optional[list] = None) -> Set[str]:
    conns = read_connections() if conns is None else conns
    ports = set(web_ports)
    out = set()  # type: Set[str]
    for c in conns:
        if c.status == psutil.CONN_ESTABLISHED and c.raddr and c.laddr and c.laddr.port in ports:
            ip = normalize_ip(c.raddr.ip)
            if ip:
                out.add(ip)
    return out
