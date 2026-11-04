import hashlib
import io
import json
import os
import plistlib
import pty
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "tok-SENTINEL-123"
KEY = "key-SENTINEL-456"


def read(name):
    return (ROOT / name).read_text()


def stub(directory, name, body="exit 0"):
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/bash\n" + body + "\n")
    path.chmod(0o755)
    return path


# -- compose and image ------------------------------------------------------


def compose(name="docker-compose.yml"):
    return yaml.safe_load(read(name))


def test_compose_nexus_has_no_public_port_with_domain():
    services = compose()["services"]
    assert "ports" not in services["nexus"]
    assert services["caddy"]["profiles"] == ["https"]
    assert set(services["caddy"]["ports"]) == {"80:80", "443:443"}


def test_local_override_binds_loopback_by_default():
    ports = compose("docker-compose.local.yml")["services"]["nexus"]["ports"]
    assert ports == ["${HTTP_BIND:-127.0.0.1:8000}:8000"]


def test_compose_pins_images_and_project_name():
    cfg = compose()
    assert cfg["name"] == "nexus"  # volumes must not change with the checkout directory's name
    for service in cfg["services"].values():
        tag = service["image"].rpartition(":")[2]
        assert re.fullmatch(r"\d+\.\d+\.\d+(-[a-z]+)?", tag), service["image"]


def test_image_ships_what_the_endpoints_serve():
    dockerfile = read("Dockerfile")
    for path in ("nexus_agent", "requirements-agent.txt", "install-agent.sh"):
        assert re.search(rf"^COPY {re.escape(path)}\b", dockerfile, re.M), path
    ignore = read(".dockerignore").split()
    assert "**/__pycache__" in ignore
    assert "psycopg[binary]" in read("requirements.txt")


# -- endpoints --------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    pytest.importorskip("torch")
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as c:
        yield c


def test_install_agent_endpoint_public_and_contains_no_secret(client):
    r = client.get("/install-agent.sh")
    assert r.status_code == 200
    assert "test-password" not in r.text
    assert "__NEXUS_PUBLIC_URL__" not in r.text


@pytest.mark.parametrize(
    "headers", [{"Host": "evil.example"}, {"X-Forwarded-Host": "evil.example"}, {"X-Forwarded-Proto": "evil.example"}]
)
def test_hostile_host_never_reaches_script(client, monkeypatch, headers):
    from backend.config import settings

    monkeypatch.setattr(settings, "public_url", "")
    r = client.get("/install-agent.sh", headers=headers)
    assert "evil.example" not in r.text
    assert "EMBEDDED_URL=''" in r.text

    monkeypatch.setattr(settings, "public_url", "https://nexus.example.com")
    r = client.get("/install-agent.sh", headers=headers)
    assert "evil.example" not in r.text
    assert "EMBEDDED_URL='https://nexus.example.com'" in r.text


@pytest.mark.parametrize("bad", ["ftp://x", "https://x/'; rm -rf /", "https://a b", "x.example.com", "https://x/p"])
def test_public_url_rejects_anything_but_an_origin(bad):
    pytest.importorskip("torch")
    from backend.config import Settings

    with pytest.raises(ValueError):
        Settings(public_url=bad)


def test_public_url_accepts_origin():
    pytest.importorskip("torch")
    from backend.config import Settings

    assert Settings(public_url="https://n.example.com:8443/").public_url == "https://n.example.com:8443"
    assert Settings(public_url="").public_url == ""


def test_agent_tarball_excludes_backend(client):
    planted = ROOT / "nexus_agent" / "__pycache__"
    planted.mkdir(exist_ok=True)
    r = client.get("/agent.tar.gz")
    assert r.status_code == 200
    assert hashlib.sha256(r.content).hexdigest() == r.headers["X-Nexus-Agent-SHA256"]
    with tarfile.open(fileobj=io.BytesIO(r.content)) as tar:
        names = tar.getnames()
        assert all(m.isfile() for m in tar.getmembers())
    assert "requirements-agent.txt" in names
    assert "nexus_agent/__main__.py" in names
    assert "nexus_agent/data/exploit_patterns.txt" in names
    for name in names:
        assert name == "requirements-agent.txt" or name.startswith("nexus_agent/")
        assert not re.search(r"__pycache__|\.pyc$|\.env|tests?/|\.joblib$", name), name


def test_agent_tarball_is_stable(client):
    assert client.get("/agent.tar.gz").content == client.get("/agent.tar.gz").content


# -- install.sh -------------------------------------------------------------


@pytest.fixture
def central(tmp_path):
    """A checkout copy with a docker stub that logs its arguments."""
    shutil.copy(ROOT / "install.sh", tmp_path)
    shutil.copy(ROOT / "docker-compose.yml", tmp_path)
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "docker", f'echo "$*" >> {tmp_path}/docker.log')
    stub(bin_dir, "ss")
    return tmp_path


def run_install(checkout, *args, stdin=subprocess.DEVNULL):
    env = {"PATH": f"{checkout}/bin:/usr/bin:/bin", "HOME": str(checkout)}
    return subprocess.run(
        ["bash", str(checkout / "install.sh"), *args],
        cwd="/", env=env, stdin=stdin, capture_output=True, text=True, timeout=30,
    )


def dotenv(checkout):
    return dict(line.split("=", 1) for line in (checkout / ".env").read_text().splitlines() if "=" in line)


def test_install_generates_password_and_mode_600(central):
    r = run_install(central)
    assert r.returncode == 0, r.stderr
    env = dotenv(central)
    assert len(env["DASHBOARD_PASSWORD"]) >= 32
    assert stat.S_IMODE((central / ".env").stat().st_mode) == 0o600
    assert r.stdout.count(env["DASHBOARD_PASSWORD"]) == 1


def test_install_without_domain_stays_on_loopback(central):
    r = run_install(central)
    env = dotenv(central)
    assert env["HTTP_BIND"] == "127.0.0.1:8000"
    assert env["INGESTION_SOURCE"] == "webhook"
    assert env["COMPOSE_FILE"] == "docker-compose.yml:docker-compose.local.yml"
    assert not env.get("COMPOSE_PROFILES") and not env.get("PUBLIC_URL") and not env.get("DOMAIN")
    assert env["TRUST_PROXY_HEADERS"] == "false"
    assert "ssh -L 8000:127.0.0.1:8000" in r.stdout
    assert "/api/agents/tokens" in r.stdout and "install-agent.sh" in r.stdout
    assert "--url http://127.0.0.1:8000" in r.stdout


def test_install_with_domain_uses_caddy_and_hides_nexus(central):
    r = run_install(central, "--domain", "nexus.example.com")
    assert r.returncode == 0, r.stderr
    env = dotenv(central)
    assert env["DOMAIN"] == "nexus.example.com"
    assert env["PUBLIC_URL"] == "https://nexus.example.com"
    assert env["TRUST_PROXY_HEADERS"] == "true"
    assert env["COMPOSE_PROFILES"] == "https"
    assert "local" not in env.get("COMPOSE_FILE", "") and "HTTP_BIND" not in env
    assert "https://nexus.example.com/install-agent.sh" in r.stdout


def test_rerun_keeps_secrets_and_volumes(central):
    run_install(central)
    with (central / ".env").open("a") as f:
        f.write("SLACK_WEBHOOK_URL=https://hooks.example/x\n# keep me\n")
    before = dotenv(central)["DASHBOARD_PASSWORD"]
    r = run_install(central, "--domain", "nexus.example.com")
    env = dotenv(central)
    assert r.returncode == 0, r.stderr
    assert env["DASHBOARD_PASSWORD"] == before and before not in r.stdout
    assert env["SLACK_WEBHOOK_URL"] == "https://hooks.example/x"
    assert "# keep me" in (central / ".env").read_text()
    log = (central / "docker.log").read_text()
    assert not re.search(r"\bdown\b|\s-v\b|--volumes|volume rm|prune", log)


def test_rerun_without_flag_keeps_domain(central):
    run_install(central, "--domain", "nexus.example.com")
    r = run_install(central)
    assert r.returncode == 0, r.stderr
    assert dotenv(central)["DOMAIN"] == "nexus.example.com"
    assert dotenv(central)["COMPOSE_PROFILES"] == "https"


def test_rerun_republishes_nothing_when_old_env_had_public_port(central):
    (central / ".env").write_text("HTTP_BIND=80\nDASHBOARD_PASSWORD=old\n")
    r = run_install(central)
    assert r.returncode == 0, r.stderr
    assert dotenv(central)["HTTP_BIND"] == "127.0.0.1:8000"
    assert dotenv(central)["DASHBOARD_PASSWORD"] == "old"


def test_non_tty_does_not_prompt(central):
    r = run_install(central)  # stdin is /dev/null; a prompt would take the empty answer silently
    assert "domain" not in r.stdout.split("Nexus is running")[0].lower()


def test_tty_prompts_for_domain(central):
    primary, secondary = pty.openpty()
    os.write(primary, b"nexus.example.com\n")
    try:
        r = run_install(central, stdin=secondary)
    finally:
        os.close(primary)
        os.close(secondary)
    assert r.returncode == 0, r.stderr
    assert dotenv(central)["DOMAIN"] == "nexus.example.com"


@pytest.mark.parametrize("bad", ["a b.com", "x.com;rm -rf /", "$(id).com", "nodots", "-x.com", "x.com\nFOO=1"])
def test_bad_domain_refused(central, bad):
    r = run_install(central, "--domain", bad)
    assert r.returncode != 0 and "domain" in r.stderr.lower()
    assert not (central / "docker.log").exists() or "up" not in (central / "docker.log").read_text()
    assert not (central / ".env").exists()


def test_busy_port_refused_before_touching_anything(central):
    stub(central / "bin", "ss", 'echo "LISTEN 0 511 *:80 *:*"')
    r = run_install(central, "--domain", "nexus.example.com")
    assert r.returncode != 0 and "80" in r.stderr
    assert not (central / ".env").exists()


def test_missing_docker_is_a_clear_error(central):
    (central / "bin" / "docker").unlink()
    (central / "bin" / "real").mkdir()
    r = subprocess.run(
        ["/bin/bash", str(central / "install.sh")],
        env={"PATH": f"{central}/bin/real"}, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
    )
    assert r.returncode != 0 and "docker" in r.stderr.lower()


def test_missing_compose_is_a_clear_error(central):
    stub(central / "bin", "docker", '[ "$1" = compose ] && exit 1; exit 0')
    r = run_install(central)
    assert r.returncode != 0 and "compose" in r.stderr.lower()


def test_outside_checkout_is_a_clear_error(central):
    (central / "docker-compose.yml").unlink()
    r = run_install(central)
    assert r.returncode != 0 and "git clone" in r.stderr


def test_install_never_prompts_for_aws():
    text = read("install.sh")
    assert "AWS_ACCESS_KEY" not in text and "AWS" not in text and "cloudwatch" not in text.lower()
    assert "get.docker.com" not in text


# -- install-agent.sh -------------------------------------------------------


def agent_shell(tmp_path, body, path=None, env=None):
    """Source the installer without its last line, point its paths into tmp_path, then run body."""
    lib = tmp_path / "lib.sh"
    lib.write_text("".join(read("install-agent.sh").splitlines(True)[:-1]))
    prelude = f"""
source {lib}
INSTALL_DIR={tmp_path}/opt
ENV_FILE={tmp_path}/agent.env
STATE_DIR={tmp_path}/state
UNIT_FILE={tmp_path}/agent.service
"""
    run_env = {"PATH": path or "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path), **(env or {})}
    return subprocess.run(["/bin/bash", "-c", prelude + body], env=run_env, capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize(
    "url,insecure,expected",
    [
        ("https://n.example.com", "", "https://n.example.com"),
        ("https://n.example.com/", "", "https://n.example.com"),
        ("https://n.example.com/api/ingest", "", "https://n.example.com"),
        ("http://127.0.0.1:8000", "", "http://127.0.0.1:8000"),
        ("http://localhost:8000", "", "http://localhost:8000"),
        ("http://[::1]:8000", "", "http://[::1]:8000"),
        ("http://n.example.com", "1", "http://n.example.com"),
        ("http://n.example.com", "", None),
        ("http://127.0.0.1.evil.example", "", None),
        ("ftp://n.example.com", "1", None),
        ("https://u:p@n.example.com", "", None),
        ("https://n.example.com?x=1", "", None),
        ("https://n.example.com\nNEXUS_MAX_MODE=enforce", "", None),
        ("https://n example.com", "", None),
        ("n.example.com", "", None),
    ],
)
def test_url_policy(tmp_path, url, insecure, expected):
    r = agent_shell(tmp_path, f'normalize_url "$U" "{insecure}"', env={"U": url})
    if expected is None:
        assert r.returncode != 0 and r.stdout == ""
    else:
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == expected


def make_tar(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for name, kind in members:
            info = tarfile.TarInfo(name)
            data = b"x"
            if kind == "file":
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tar.addfile(info)
    return hashlib.sha256(path.read_bytes()).hexdigest()


GOOD = [("requirements-agent.txt", "file"), ("nexus_agent/__main__.py", "file"), ("nexus_agent/data/x.txt", "file")]


def extract(tmp_path, sha_for_tar):
    dest = tmp_path / "dest"
    dest.mkdir()
    r = agent_shell(tmp_path, f'verify_and_extract {tmp_path}/a.tgz {sha_for_tar} {dest}')
    return r, dest


def test_extract_good_tar(tmp_path):
    sha = make_tar(tmp_path / "a.tgz", GOOD)
    r, dest = extract(tmp_path, sha)
    assert r.returncode == 0, r.stderr
    assert (dest / "nexus_agent/data/x.txt").is_file() and (dest / "requirements-agent.txt").is_file()


@pytest.mark.parametrize(
    "extra",
    [
        ("/etc/evil", "file"),
        ("../evil", "file"),
        ("nexus_agent/../../evil", "file"),
        ("nexus_agent/link", "symlink"),
        ("backend/main.py", "file"),
    ],
)
def test_extract_refuses_unsafe_member_and_writes_nothing(tmp_path, extra):
    sha = make_tar(tmp_path / "a.tgz", GOOD + [extra])
    r, dest = extract(tmp_path, sha)
    assert r.returncode != 0
    assert list(dest.iterdir()) == []
    assert not (tmp_path / "evil").exists()


def test_extract_refuses_sha_mismatch(tmp_path):
    make_tar(tmp_path / "a.tgz", GOOD)
    r, dest = extract(tmp_path, "0" * 64)
    assert r.returncode != 0 and "sha256" in r.stderr.lower()
    assert list(dest.iterdir()) == []


def test_refuses_non_root(tmp_path):
    stub(tmp_path / "bin", "id", "echo 1000")
    r = agent_shell(tmp_path, "main --token t --url https://n.example.com", path=f"{tmp_path}/bin:/usr/bin:/bin")
    assert r.returncode != 0 and "root" in r.stderr


def test_refuses_without_systemd(tmp_path):
    r = agent_shell(tmp_path, "require_root() { :; }; main --token t --url https://n.example.com",
                    path=f"{tmp_path}/none:/usr/bin:/bin")
    if shutil.which("systemctl") and Path("/run/systemd/system").is_dir():
        pytest.skip("this host has systemd")
    assert r.returncode != 0 and "systemd" in r.stderr


NO_HOST_CHECKS = "require_root() { :; }; require_systemd() { :; }; ensure_packages() { echo PACKAGES; }; "


def test_old_python_is_a_clear_error(tmp_path):
    stub(tmp_path / "bin", "python3", "exit 1")
    r = agent_shell(tmp_path, "require_root() { :; }; require_python", path=f"{tmp_path}/bin:/usr/bin:/bin")
    assert r.returncode != 0 and "3.9" in r.stderr


def test_http_refused_before_changing_anything(tmp_path):
    r = agent_shell(tmp_path, NO_HOST_CHECKS + "main --token t --url http://n.example.com")
    assert r.returncode != 0 and "https" in r.stderr and "PACKAGES" not in r.stdout


def test_no_embedded_url_requires_flag(tmp_path):
    r = agent_shell(tmp_path, NO_HOST_CHECKS + "EMBEDDED_URL=''; main --token t")
    assert r.returncode != 0 and "--url" in r.stderr and "PACKAGES" not in r.stdout


def test_missing_token_refused_on_fresh_install(tmp_path):
    r = agent_shell(tmp_path, NO_HOST_CHECKS + "main --url https://n.example.com")
    assert r.returncode != 0 and "token" in r.stderr.lower() and "PACKAGES" not in r.stdout


def test_bad_max_mode_refused(tmp_path):
    r = agent_shell(tmp_path, NO_HOST_CHECKS + "main --token t --url https://n.example.com --max-mode yolo")
    assert r.returncode != 0 and "max-mode" in r.stderr


def test_unknown_flag_refused(tmp_path):
    r = agent_shell(tmp_path, NO_HOST_CHECKS + "main --nope")
    assert r.returncode != 0 and "--nope" in r.stderr


def test_enrolled_host_keeps_its_central(tmp_path):
    (tmp_path / "agent.env").write_text("NEXUS_URL=https://old.example.com/api/ingest\nNEXUS_API_KEY=k\n")
    r = agent_shell(tmp_path, 'parse_args; resolve_target; echo "$URL $ENROLLED"')
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["https://old.example.com", "1"]
    r = agent_shell(tmp_path, "parse_args --url https://other.example.com; resolve_target")
    assert r.returncode != 0 and "uninstall" in r.stderr


def test_env_token_wins_over_flag(tmp_path):
    r = agent_shell(tmp_path, 'parse_args --token flag; echo "$TOKEN"', env={"NEXUS_ENROLL_TOKEN": "fromenv"})
    assert r.stdout.strip() == "fromenv"


def test_other_distro_gets_instructions_and_nothing_changes(tmp_path):
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "python3", "exit 1")  # no ensurepip, no apt, no dnf, no nft on this PATH
    r = agent_shell(tmp_path, "ensure_packages; echo CONTINUED", path=str(bin_dir))
    assert r.returncode != 0 and "CONTINUED" not in r.stdout
    assert "python3-venv" in r.stderr and "nftables" in r.stderr


@pytest.mark.parametrize("manager", ["apt-get", "dnf"])
def test_packages_install_only_what_is_missing(tmp_path, manager):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "pkg.log"
    stub(bin_dir, "python3", "exit 0")
    stub(bin_dir, manager, f'echo "$*" >> {log}')
    r = agent_shell(tmp_path, "ensure_packages", path=str(bin_dir))
    assert r.returncode == 0, r.stderr
    text = log.read_text()
    assert "nftables" in text and "python3-venv" not in text


def fake_venv(tmp_path, stdout, code=0):
    venv = tmp_path / "opt" / "venv" / "bin"
    venv.mkdir(parents=True)
    body = f'printf "%s " "$@" >> {tmp_path}/argv.log; echo "${{NEXUS_ENROLL_TOKEN:-}}" >> {tmp_path}/tokenenv.log\n'
    body += f"cat <<'OUT'\n{stdout}\nOUT\nexit {code}"
    path = venv / "python"
    path.write_text("#!/bin/bash\n" + body + "\n")
    path.chmod(0o755)


def test_enroll_passes_token_by_env_and_never_prints_key(tmp_path):
    fake_venv(tmp_path, json.dumps({"node_id": "web-1", "api_key": KEY}))
    r = agent_shell(tmp_path, f"parse_args --token {TOKEN} --max-mode observe; URL=https://n.example.com; enroll_and_write_env")
    assert r.returncode == 0, r.stderr
    assert TOKEN not in (tmp_path / "argv.log").read_text()
    assert TOKEN in (tmp_path / "tokenenv.log").read_text()
    assert KEY not in r.stdout + r.stderr and TOKEN not in r.stdout + r.stderr
    env_file = tmp_path / "agent.env"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    lines = env_file.read_text().splitlines()
    assert f"NEXUS_API_KEY={KEY}" in lines
    assert "NEXUS_URL=https://n.example.com" in lines
    assert "NEXUS_NODE_ID=web-1" in lines
    assert "NEXUS_MAX_MODE=observe" in lines


@pytest.mark.parametrize(
    "answer",
    ["not json", json.dumps({"node_id": "a\nNEXUS_MAX_MODE=enforce", "api_key": "k"}), json.dumps({"node_id": "a"})],
)
def test_enroll_refuses_a_bad_answer(tmp_path, answer):
    fake_venv(tmp_path, answer)
    r = agent_shell(tmp_path, "parse_args --token t; URL=https://n.example.com; enroll_and_write_env")
    assert r.returncode != 0
    assert not (tmp_path / "agent.env").exists()


def test_rollback_removes_fresh_install_on_failure(tmp_path):
    fake_venv(tmp_path, "", code=1)
    (tmp_path / "agent.env.tmp").write_text("x")
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "userdel", f'echo "$*" >> {tmp_path}/userdel.log')
    stub(bin_dir, "id")
    r = agent_shell(
        tmp_path,
        "trap on_exit EXIT; ROLLBACK=1; CREATED_USER=1; parse_args --token t; URL=https://n.example.com; enroll_and_write_env",
        path=f"{bin_dir}:/usr/bin:/bin",
    )
    assert r.returncode != 0
    assert not (tmp_path / "opt").exists() and not (tmp_path / "agent.env.tmp").exists()
    assert "nexus-agent" in (tmp_path / "userdel.log").read_text()


def test_failed_upgrade_keeps_the_install(tmp_path):
    fake_venv(tmp_path, "", code=1)
    (tmp_path / "agent.env").write_text("NEXUS_API_KEY=k\n")
    r = agent_shell(tmp_path, "trap on_exit EXIT; ROLLBACK=0; false || die boom")
    assert r.returncode != 0
    assert (tmp_path / "opt").exists() and (tmp_path / "agent.env").exists()


def test_uninstall_works_when_partly_installed(tmp_path):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "calls.log"
    for tool in ("systemctl", "userdel"):
        stub(bin_dir, tool, f'echo "{tool} $*" >> {log}')
    stub(bin_dir, "id")
    # The venv is gone, so the table must still go through nft itself.
    stub(bin_dir, "nft", f'echo "nft $*" >> {log}; exit 0')
    (tmp_path / "state").mkdir()
    (tmp_path / "opt").mkdir()
    (tmp_path / "agent.env").write_text("NEXUS_API_KEY=k\n")
    (tmp_path / "agent.service").write_text("[Unit]\n")
    r = agent_shell(tmp_path, "uninstall", path=f"{bin_dir}:/usr/bin:/bin")
    assert r.returncode == 0, r.stderr
    for gone in ("state", "opt", "agent.env", "agent.service"):
        assert not (tmp_path / gone).exists(), gone
    calls = log.read_text()
    assert "nft delete table inet nexus" in calls
    assert "userdel nexus-agent" in calls


def test_uninstall_runs_agent_uninstall_after_stop(tmp_path):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "calls.log"
    stub(bin_dir, "systemctl", f'echo "systemctl $*" >> {log}')
    stub(bin_dir, "userdel")
    venv = tmp_path / "opt" / "venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text(f'#!/bin/bash\necho "python $*" >> {log}\n')
    (venv / "python").chmod(0o755)
    (tmp_path / "opt" / "nexus_agent").mkdir()
    r = agent_shell(tmp_path, "uninstall", path=f"{bin_dir}:/usr/bin:/bin")
    assert r.returncode == 0, r.stderr
    calls = log.read_text().splitlines()
    stop = calls.index("systemctl stop nexus-agent")
    teardown = calls.index("python -m nexus_agent uninstall")
    # A running enforcing agent would recreate the table right after it was deleted.
    assert stop < teardown


def test_installer_leaves_other_firewalls_alone():
    text = read("install-agent.sh")
    assert "flush ruleset" not in text
    assert not re.search(r"systemctl\s+\S+\s+(nftables|ufw|firewalld|iptables)", text)
    assert not re.search(r"\b(ufw|firewall-cmd|iptables)\b", text)


def test_installer_states_observe_default():
    assert "no traffic will be blocked until you enable enforce in the panel" in read("install-agent.sh")


def test_enroll_command_has_no_token_argument():
    assert not re.search(r"nexus_agent enroll[^\n]*--token", read("install-agent.sh"))


# -- truncation -------------------------------------------------------------


@pytest.mark.parametrize("script", ["install.sh", "install-agent.sh"])
def test_last_line_is_the_only_entry(script):
    assert read(script).rstrip("\n").splitlines()[-1] == '{ main "$@"; }'


@pytest.mark.parametrize("script", ["install.sh", "install-agent.sh"])
def test_truncated_download_runs_nothing(tmp_path, script):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "ran.log"
    tools = "docker curl systemctl apt-get dnf nft useradd userdel rm mv cp mkdir chmod openssl python3 id tee sed awk".split()
    for tool in tools:
        stub(bin_dir, tool, f'echo "{tool}" >> {log}')
    text = read(script)
    body = text.encode()
    # Every line end, and every byte of the last line: `main` alone would run with its arguments lost.
    # Only the final newline may be missing, since the whole script has arrived by then.
    cuts = {m.end() for m in re.finditer(rb"\n", body)} | set(range(len(body) - 20, len(body)))
    cuts -= {len(body), len(body) - 1}
    target = tmp_path / "cut.sh"
    for cut in sorted(cuts):
        target.write_bytes(body[:cut])
        r = subprocess.run(["/bin/bash", str(target)], env={"PATH": str(bin_dir)}, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, cwd=tmp_path, timeout=10)
        assert not log.exists(), f"{script} cut at byte {cut} ran {log.read_text()}"
        assert r.stdout == "", f"{script} cut at byte {cut} printed {r.stdout!r}"


# -- unit and other deploy files --------------------------------------------


def test_embedded_unit_matches_deploy_file():
    match = re.search(r"<<'UNIT'\n(.*?)^UNIT$", read("install-agent.sh"), re.S | re.M)
    assert match and match.group(1) == read("deploy/systemd/nexus-agent.service")


def test_unit_has_required_lines():
    lines = read("deploy/systemd/nexus-agent.service").splitlines()
    for wanted in (
        "User=nexus-agent",
        "ExecStart=/opt/nexus-agent/venv/bin/python -m nexus_agent run",
        "EnvironmentFile=/etc/nexus-agent.env",
        "StateDirectory=nexus-agent",
        "After=network-online.target",
        "Wants=network-online.target",
        "Restart=always",
        "RestartSec=5",
        "AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH",
        "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
    ):
        assert wanted in lines, wanted
    assert "DynamicUser=yes" not in lines


def test_no_deploy_file_runs_deleted_agent_py():
    assert "agent.py" not in read("deploy/systemd/nexus-agent.service")
    assert "agent.py" not in read("deploy/launchd/com.nexus.agent.plist")


def test_launchd_runs_the_package_metrics_only():
    plist = plistlib.loads((ROOT / "deploy/launchd/com.nexus.agent.plist").read_bytes())
    assert plist["ProgramArguments"][1:] == ["-m", "nexus_agent", "run"]
    assert plist["WorkingDirectory"] == "/usr/local/nexus-agent"
    assert plist["EnvironmentVariables"]["NEXUS_MAX_MODE"] == "observe"


def test_cloudwatch_config_matches_what_central_queries():
    from backend.config import Settings

    cfg = json.loads(read("deploy/cloudwatch-agent.json"))
    defaults = Settings.model_fields
    assert cfg["metrics"]["namespace"] == defaults["cloudwatch_memory_namespace"].default
    assert defaults["cloudwatch_memory_metric"].default in cfg["metrics"]["metrics_collected"]["mem"]["measurement"]
    assert cfg["metrics"]["append_dimensions"] == {"InstanceId": "${aws:InstanceId}"}
    # Central queries by InstanceId alone; a host dimension would make every lookup miss.
    assert cfg["agent"]["omit_hostname"] is True
    probe = read("deploy/latency_probe.sh")
    assert defaults["cloudwatch_latency_namespace"].default in probe
    assert defaults["cloudwatch_latency_metric"].default in probe


def test_default_path_never_needs_aws():
    from backend.config import Settings

    assert Settings.model_fields["ingestion_source"].default == "webhook"
    assert "cloudwatch" not in read("install-agent.sh").lower()


# -- shellcheck -------------------------------------------------------------


def test_shellcheck_clean():
    # No skip: this image has it (Dockerfile.test) and CI installs it, so a missing binary must fail.
    assert shutil.which("shellcheck"), "shellcheck is not installed"
    files = ["install.sh", "install-agent.sh", "deploy/latency_probe.sh", "scripts/test.sh", "tests/e2e/run.sh",
             "tests/e2e/check.sh"]
    r = subprocess.run(["shellcheck", "-x", *files], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
