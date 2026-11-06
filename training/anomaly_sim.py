from __future__ import annotations

import random
import time
from typing import Iterator, List, Tuple

Record = Tuple[float, str, str, str, str]

DAY = 86400.0
START = 1_780_000_000.0
BROWSERS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
)
PAGES = ("/", "/menu", "/about", "/contact", "/orders", "/account", "/search?q=pizza", "/cart")
ASSETS = ("/app.js", "/app.css", "/logo.svg", "/font.woff2", "/hero.webp", "/favicon.ico")
PROBES = ("/.env", "/.git/config", "/phpmyadmin", "/pma", "/.aws/credentials", "/wso.php", "/c99.php", "/shell.php",
          "/.htpasswd", "/.ds_store", "/myadmin", "/.ssh/id_rsa", "/.git/head", "/phpmyadmin/index.php", "/.htaccess")
EXPLOITS = ("/item?id=1'%20or%201=1", "/item?id=1+UNION+SELECT+2", "/item?f=/etc/passwd", "/item?f=../../../etc/passwd",
            "/item?c=$(id)", "/item?x=%3Cscript%3Ealert(1)", "/item?j=${jndi:ldap://x/a}", "/item?id=2'%20or%202=2")
USERS = ("admin", "test", "oracle", "postgres", "ubuntu", "git", "user", "ftp", "deploy", "nginx", "guest", "pi", "mysql",
         "jenkins", "hadoop", "www", "support", "dev", "backup", "minecraft")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _ssh_line(ts: float, text: str) -> str:
    t = time.gmtime(ts)
    return "%s %2d %02d:%02d:%02d host sshd[%d]: %s" % (_MONTHS[t.tm_mon - 1], t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
                                                        int(ts) % 30000 + 1000, text)


def _web_line(ts: float, ip: str, method: str, path: str, status: int, ua: str) -> str:
    t = time.gmtime(ts)
    return '%s - - [%02d/%s/%d:%02d:%02d:%02d +0000] "%s %s HTTP/1.1" %d 512 "-" "%s"' % (
        ip, t.tm_mday, _MONTHS[t.tm_mon - 1], t.tm_year, t.tm_hour, t.tm_min, t.tm_sec, method, path, status, ua)


class _Sim:
    def __init__(self, seed: int, days: int):
        self.rng = random.Random(seed)
        self.days = days
        self.out = []  # type: List[Record]
        self._ip = self.rng.randrange(1 << 16)

    def ip(self) -> str:
        self._ip += self.rng.randrange(1, 64)
        return "11.%d.%d.%d" % ((self._ip >> 16) & 255, (self._ip >> 8) & 255, self._ip & 255 or 1)

    def when(self) -> float:
        return START + self.rng.random() * self.days * DAY

    def web(self, ts, ip, method, path, status, ua, label):
        self.out.append((ts, "web", _web_line(ts, ip, method, path, status, ua), label, ip))

    def ssh(self, ts, ip, text, label):
        self.out.append((ts, "ssh", _ssh_line(ts, text), label, ip))

    def try_invalid(self, ts, ip, user, label):
        port = self.rng.randrange(1024, 65535)
        self.ssh(ts, ip, "Invalid user %s from %s port %d" % (user, ip, port), label)
        self.ssh(ts + 0.5, ip, "Connection closed by invalid user %s %s port %d [preauth]" % (user, ip, port), label)

    def try_closed(self, ts, ip, user, label):
        port = self.rng.randrange(1024, 65535)
        self.ssh(ts, ip, "Connection closed by authenticating user %s %s port %d [preauth]" % (user, ip, port), label)

    def browser_session(self, ip=None, label="customer_browser", ts=None):
        r, ip, ts = self.rng, ip or self.ip(), ts or self.when()
        ua = r.choice(BROWSERS)
        for _ in range(r.randint(1, 8)):
            self.web(ts, ip, "GET", r.choice(PAGES), 200, ua, label)
            for asset in r.sample(ASSETS, r.randint(1, len(ASSETS))):
                ts += r.uniform(0.02, 0.4)
                self.web(ts, ip, "GET", asset, 200 if r.random() < 0.97 else 404, ua, label)
            ts += r.expovariate(1 / 40.0)
        return ip, ts, ua

    def api_client(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        ua = r.choice(("okhttp/4.12", "python-requests/2.32", "Dart/3.5"))
        gap = r.choice((30.0, 60.0, 300.0))
        for _ in range(r.randint(10, 60)):
            self.web(ts, ip, "GET", "/api/status", 200, ua, "customer_api")
            ts += gap + r.uniform(-0.5, 0.5)

    def login_typos(self):
        r = self.rng
        ip, ts, ua = self.browser_session(label="customer_login_typos")
        for _ in range(r.randint(3, 7)):
            ts += r.uniform(5, 90)
            self.web(ts, ip, "POST", "/login", 401, ua, "customer_login_typos")

    def curious_developer(self):
        r = self.rng
        ip, ts, ua = self.browser_session(label="customer_curious")
        for path in r.sample(PROBES, r.randint(3, 5)):
            ts += r.uniform(3, 60)
            self.web(ts, ip, "GET", path, r.choice((200, 404)), ua, "customer_curious")

    def admin_typos(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        user = r.choice(("emin", "root", "deploy"))
        for _ in range(r.randint(3, 6)):
            self.ssh(ts, ip, "Failed password for %s from %s port %d ssh2" % (user, ip, r.randrange(1024, 65535)),
                     "customer_ssh_typos")
            ts += r.uniform(4, 45)

    def admin_keys(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        user = r.choice(("emin", "root", "deploy"))
        for _ in range(r.randint(3, 6)):
            self.try_closed(ts, ip, user, "customer_ssh_keys")
            ts += r.uniform(2, 120)

    def admin_wrong_user(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for user in r.sample(("emin", "eminaydin", "ubuntu", "admin"), r.randint(3, 4)):
            self.try_invalid(ts, ip, user, "customer_ssh_wrong_user")
            ts += r.uniform(8, 120)

    def ssh_fast(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for _ in range(r.randint(40, 300)):
            self.try_invalid(ts, ip, r.choice(USERS), "attack_ssh_fast")
            ts += r.uniform(0.5, 4)

    def ssh_slow(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for user in r.sample(USERS, r.randint(4, 9)):
            self.try_invalid(ts, ip, user, "attack_ssh_slow")
            ts += r.uniform(120, 500)

    def ssh_root_only(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for _ in range(r.randint(4, 9)):
            self.try_closed(ts, ip, "root", "attack_ssh_root_only")
            ts += r.uniform(1, 30)

    def web_nikto(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for i in range(r.randint(100, 400)):
            path = r.choice(PROBES) if r.random() < 0.2 else "/cgi-bin/x%d.cgi" % i
            self.web(ts, ip, "GET", path, 404, "Mozilla/5.00 (Nikto/2.5.0)", "attack_web_nikto")
            ts += r.uniform(0.02, 0.2)

    def web_gobuster(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for i in range(r.randint(200, 800)):
            path = r.choice(PROBES) if r.random() < 0.05 else "/w%d" % i
            self.web(ts, ip, "GET", path, 404, "gobuster/3.6", "attack_web_gobuster")
            ts += r.uniform(0.01, 0.1)

    def web_sqlmap(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for _ in range(r.randint(30, 200)):
            self.web(ts, ip, "GET", r.choice(EXPLOITS), r.choice((200, 500)), "sqlmap/1.8", "attack_web_sqlmap")
            ts += r.uniform(0.05, 0.5)

    def web_spa_scan(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for path in r.sample(PROBES, r.randint(4, 15)):
            self.web(ts, ip, "GET", path, 200, r.choice(("curl/8.5", "python-requests/2.31", "-")), "attack_web_spa_scan")
            ts += r.uniform(0.1, 3)

    def web_slow_probe(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        ua = r.choice(BROWSERS)
        for path in r.sample(PROBES, r.randint(4, 8)):
            self.web(ts, ip, "GET", path, r.choice((200, 404)), ua, "attack_web_slow_probe")
            ts += r.uniform(60, 500)

    def web_login_slow(self):
        r, ip, ts = self.rng, self.ip(), self.when()
        for _ in range(r.randint(5, 25)):
            self.web(ts, ip, "POST", "/login", 401, "curl/8.5", "attack_web_login_slow")
            ts += r.uniform(10, 120)


def simulate(seed: int, days: int = 7, customers: int = 300, attacks: int = 40) -> List[Record]:
    sim = _Sim(seed, days)
    for _ in range(customers):
        sim.browser_session()
    for make, count in ((sim.api_client, customers // 6), (sim.login_typos, customers // 6), (sim.curious_developer, customers // 6),
                        (sim.admin_typos, customers // 6), (sim.admin_keys, customers // 6), (sim.admin_wrong_user, customers // 6)):
        for _ in range(count):
            make()
    for make in (sim.ssh_fast, sim.ssh_slow, sim.ssh_root_only, sim.web_nikto, sim.web_gobuster, sim.web_sqlmap, sim.web_spa_scan,
                 sim.web_slow_probe, sim.web_login_slow):
        for _ in range(attacks):
            make()
    return sorted(sim.out, key=lambda rec: rec[0])


def iter_lines(records: List[Record]) -> Iterator[Tuple[float, str, str]]:
    for ts, source, line, _label, _ip in records:
        yield ts, source, line
