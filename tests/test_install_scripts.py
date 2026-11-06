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
import sys
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
    assert cfg["name"] == "nexus-defense"
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


@pytest.fixture
def planted_agent_files():
    from backend.main import _agent_tarball

    package = ROOT / "nexus_agent"
    planted = [package / "__pycache__" / "planted.py", package / "__pycache__" / "planted.cpython-312.pyc",
               package / ".env", package / ".env.txt", package / "tests" / "test_planted.py"]
    made_tests = not (package / "tests").exists()
    for path in planted:
        path.parent.mkdir(exist_ok=True)
        path.write_text("SECRET\n")
    _agent_tarball.cache_clear()
    yield
    for path in planted:
        path.unlink()
    if made_tests:
        (package / "tests").rmdir()
    _agent_tarball.cache_clear()


def test_agent_tarball_excludes_backend(client, planted_agent_files):
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


@pytest.fixture
def central(tmp_path):
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


def test_rerun_without_domain_keeps_what_is_in_env_and_warns_about_public_http(central):
    (central / ".env").write_text(
        "HTTP_BIND=0.0.0.0:80\nDASHBOARD_PASSWORD=old\nPUBLIC_URL=https://mine.example.com\nTRUST_PROXY_HEADERS=true\n"
    )
    r = run_install(central)
    assert r.returncode == 0, r.stderr
    env = dotenv(central)
    assert env["HTTP_BIND"] == "0.0.0.0:80"
    assert env["PUBLIC_URL"] == "https://mine.example.com"
    assert env["TRUST_PROXY_HEADERS"] == "true"
    assert env["DASHBOARD_PASSWORD"] == "old"
    assert "HTTP_BIND" in r.stderr and "http" in r.stderr.lower()


def test_rerun_with_loopback_bind_does_not_warn(central):
    run_install(central)
    r = run_install(central)
    assert r.returncode == 0, r.stderr
    assert "HTTP_BIND" not in r.stderr


def test_domain_flag_overwrites_those_settings(central):
    (central / ".env").write_text("HTTP_BIND=0.0.0.0:80\nDASHBOARD_PASSWORD=old\nTRUST_PROXY_HEADERS=false\n")
    r = run_install(central, "--domain", "nexus.example.com")
    assert r.returncode == 0, r.stderr
    env = dotenv(central)
    assert "HTTP_BIND" not in env and env["TRUST_PROXY_HEADERS"] == "true"
    assert env["PUBLIC_URL"] == "https://nexus.example.com"


def test_no_domain_report_only_mentions_a_local_agent(central):
    r = run_install(central)
    assert "only" in r.stdout and "this machine" in r.stdout
    assert "other servers" not in r.stdout.lower() and "server to protect" not in r.stdout


def test_failed_up_says_where_the_password_is_without_printing_it(central):
    stub(central / "bin", "docker", '[ "$2" = up ] && exit 1; exit 0')
    r = run_install(central)
    assert r.returncode != 0
    assert f"{central}/.env" in r.stderr
    password = dotenv(central)["DASHBOARD_PASSWORD"]
    assert password not in r.stdout + r.stderr


def test_ctrl_d_at_the_prompt_is_explained(central):
    primary, secondary = pty.openpty()
    os.write(primary, b"\x04")
    try:
        r = run_install(central, stdin=secondary)
    finally:
        os.close(primary)
        os.close(secondary)
    assert r.returncode != 0
    assert "--domain" in r.stderr
    assert not (central / ".env").exists()


def docker_with(central, ps="", inspect_ok=True, volumes=""):
    stub(central / "bin", "docker", f"""echo "$*" >> {central}/docker.log
case "$1 $2" in
  "ps -a") echo {ps!r} ;;
  "volume inspect") exit {0 if inspect_ok else 1} ;;
  "volume ls") echo {volumes!r} ;;
esac
exit 0""")


def test_another_checkout_owning_the_project_is_refused(central, tmp_path_factory):
    other = tmp_path_factory.mktemp("other-checkout")
    docker_with(central, ps=str(other))
    r = run_install(central)
    assert r.returncode != 0 and str(other) in r.stderr
    assert not (central / ".env").exists()
    assert " up " not in (central / "docker.log").read_text()


def test_own_checkout_owning_the_project_is_fine(central):
    docker_with(central, ps=str(central.resolve()))
    r = run_install(central)
    assert r.returncode == 0, r.stderr


def test_other_data_volume_stops_and_changes_nothing(central):
    docker_with(central, inspect_ok=False, volumes="nexus_nexus-data")
    r = run_install(central)
    assert r.returncode != 0
    assert "nexus_nexus-data" in r.stderr and "--adopt-empty-data" in r.stderr
    assert not (central / ".env").exists()
    assert " up " not in (central / "docker.log").read_text()


def test_adopt_empty_data_proceeds(central):
    docker_with(central, inspect_ok=False, volumes="nexus_nexus-data")
    r = run_install(central, "--adopt-empty-data")
    assert r.returncode == 0, r.stderr
    assert "up -d" in (central / "docker.log").read_text()


def test_no_volumes_at_all_is_a_plain_first_install(central):
    docker_with(central, inspect_ok=False, volumes="")
    assert run_install(central).returncode == 0


def test_install_from_a_hostile_cwd_runs_nothing_from_it(central, tmp_path_factory):
    hostile = tmp_path_factory.mktemp("hostile")
    marker = hostile / "RAN"
    for name in ("secrets", "venv", "pip", "os"):
        (hostile / f"{name}.py").write_text(f"open({str(marker)!r}, 'w')\n")
    stub(central / "bin", "openssl", "exit 1")
    env = {"PATH": f"{central}/bin:/usr/local/bin:/usr/bin:/bin", "HOME": str(central)}
    r = subprocess.run(["/bin/bash", str(central / "install.sh")], cwd=hostile, env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert not marker.exists()
    assert len(dotenv(central)["DASHBOARD_PASSWORD"]) >= 32
    assert not (hostile / ".env").exists()


def test_non_tty_does_not_prompt(central):
    r = run_install(central)
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
    assert r.returncode != 0 and "Docker is required" in r.stderr


def test_missing_compose_is_a_clear_error(central):
    stub(central / "bin", "docker", '[ "$1" = compose ] && exit 1; exit 0')
    r = run_install(central)
    assert r.returncode != 0 and "compose" in r.stderr.lower()


def test_outside_checkout_is_a_clear_error(central):
    (central / "docker-compose.yml").unlink()
    r = run_install(central)
    assert r.returncode != 0 and "git clone" in r.stderr


def test_readme_says_upgrade_needs_git_pull():
    assert "git pull" in read("README.md")


def test_ci_updates_apt_before_installing_shellcheck():
    assert re.search(r"apt-get update[^\n]*\n\s*sudo apt-get install -y shellcheck", read(".github/workflows/ci.yml"))


def test_install_never_prompts_for_aws():
    text = read("install.sh")
    assert "AWS_ACCESS_KEY" not in text and "AWS" not in text and "cloudwatch" not in text.lower()
    assert "get.docker.com" not in text


def agent_shell(tmp_path, body, path=None, env=None, timeout=30):
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
    return subprocess.run(["/bin/bash", "-c", prelude + body], env=run_env, capture_output=True, text=True,
                          timeout=timeout)


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
        ("http://[::1", "1", None),
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


def os_release(tmp_path, text):
    path = tmp_path / "os-release"
    path.write_text(text)
    return f"OS_RELEASE={path}; "


@pytest.mark.parametrize(
    "release,fix",
    [
        ('ID=ubuntu\nVERSION_ID="20.04"\n', "apt install python3.9 python3.9-venv"),
        ('ID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="8.10"\n', "dnf install python39"),
        ('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="8.9"\n', "dnf install python39"),
        ("ID=arch\n", "Python 3.9"),
    ],
)
def test_no_usable_python_prints_the_exact_fix(tmp_path, release, fix):
    stub(tmp_path / "bin", "python3", "exit 1")
    r = agent_shell(tmp_path, os_release(tmp_path, release) + "require_python; echo CONTINUED", path=f"{tmp_path}/bin")
    assert r.returncode != 0 and "CONTINUED" not in r.stdout
    assert fix in r.stderr


def test_python_search_takes_the_first_new_enough(tmp_path):
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "python3", "exit 1")
    stub(bin_dir, "python3.13", "exit 1")
    stub(bin_dir, "python3.11")
    stub(bin_dir, "python3.9")
    r = agent_shell(tmp_path, 'require_python; echo "$PYTHON"', path=str(bin_dir))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "python3.11"


def test_python_search_prefers_plain_python3(tmp_path):
    bin_dir = tmp_path / "bin"
    stub(bin_dir, "python3")
    stub(bin_dir, "python3.13")
    r = agent_shell(tmp_path, 'require_python; echo "$PYTHON"', path=str(bin_dir))
    assert r.stdout.strip() == "python3"


@pytest.mark.parametrize(
    "manager,python,package",
    [
        ("apt-get", "python3", "python3-venv"),
        ("apt-get", "python3.9", "python3.9-venv"),
        ("dnf", "python3", "python3-libs"),
        ("dnf", "python3.9", "python39-libs"),
        ("dnf", "python3.11", "python3.11-libs"),
    ],
)
def test_venv_package_follows_family_and_interpreter(tmp_path, manager, python, package):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "pkg.log"
    stub(bin_dir, python, "exit 1")
    stub(bin_dir, "nft")
    stub(bin_dir, manager, f'echo "$*" >> {log}')
    r = agent_shell(tmp_path, f"PYTHON={python}; ensure_packages", path=str(bin_dir))
    assert r.returncode == 0, r.stderr
    assert package in log.read_text().split()


def test_venv_check_uses_the_chosen_interpreter(tmp_path):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "pkg.log"
    stub(bin_dir, "python3", "exit 1")
    stub(bin_dir, "python3.9")
    stub(bin_dir, "nft")
    stub(bin_dir, "apt-get", f'echo "$*" >> {log}')
    r = agent_shell(tmp_path, "PYTHON=python3.9; ensure_packages", path=str(bin_dir))
    assert r.returncode == 0, r.stderr
    assert not log.exists()


def test_missing_curl_stops_before_packages(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub(bin_dir, "python3", f'exec {sys.executable} "$@"')
    r = agent_shell(
        tmp_path,
        NO_HOST_CHECKS + f'PATH={bin_dir}; command() {{ [ "$2" != curl ] && builtin command "$@"; }}; '
        "main --token t --url https://n.example.com",
        path=f"{bin_dir}:/usr/local/bin:/usr/bin:/bin",
    )
    assert r.returncode != 0 and "curl" in r.stderr
    assert "PACKAGES" not in r.stdout


MARKED = "nexus-agent:x:999:999:Nexus agent (managed):/var/lib/nexus-agent:/usr/sbin/nologin"
FOREIGN = "nexus-agent:x:1001:1001:Somebody Else:/home/nexus-agent:/bin/bash"


def getent_says(tmp_path, line):
    stub(tmp_path / "bin", "getent", f'[ "$1" = passwd ] && echo "{line}"; exit 0')


def test_foreign_user_refused_before_any_change(tmp_path):
    getent_says(tmp_path, FOREIGN)
    r = agent_shell(tmp_path, NO_HOST_CHECKS + "main --token t --url https://n.example.com",
                    path=f"{tmp_path}/bin:/usr/local/bin:/usr/bin:/bin")
    assert r.returncode != 0 and "nexus-agent" in r.stderr
    assert "PACKAGES" not in r.stdout


def test_own_user_passes_the_check(tmp_path):
    getent_says(tmp_path, MARKED)
    r = agent_shell(tmp_path, "check_existing_user; echo FINE", path=f"{tmp_path}/bin:/usr/local/bin:/usr/bin:/bin")
    assert "FINE" in r.stdout


def test_created_user_gets_the_marker(tmp_path):
    log = tmp_path / "useradd.log"
    stub(tmp_path / "bin", "useradd", f'printf "%s\\n" "$@" >> {log}')
    stub(tmp_path / "bin", "getent", "exit 2")
    r = agent_shell(tmp_path, "ensure_user", path=f"{tmp_path}/bin:/usr/local/bin:/usr/bin:/bin")
    assert r.returncode == 0, r.stderr
    assert "Nexus agent (managed)" in log.read_text().splitlines()


def test_uninstall_leaves_a_foreign_user_and_says_so(tmp_path):
    bin_dir = tmp_path / "bin"
    log = tmp_path / "calls.log"
    getent_says(tmp_path, FOREIGN)
    stub(bin_dir, "systemctl")
    stub(bin_dir, "userdel", f'echo "userdel $*" >> {log}')
    r = agent_shell(tmp_path, "uninstall", path=f"{bin_dir}:/usr/bin:/bin")
    assert r.returncode == 0, r.stderr
    assert not log.exists()
    assert "nexus-agent" in r.stdout + r.stderr and "not" in (r.stdout + r.stderr).lower()


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
    stub(bin_dir, "python3", "exit 1")
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
    getent_says(tmp_path, MARKED)
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
    getent_says(tmp_path, MARKED)
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


def full_flow_lib(tmp_path):
    return f"""
require_root() {{ :; }}; require_systemd() {{ :; }}; require_curl() {{ :; }}; ensure_user() {{ :; }}; ensure_packages() {{ :; }}
check_existing_user() {{ :; }}; start_service() {{ :; }}; wait_for_report() {{ :; }}; report() {{ echo REPORTED; }}
download_agent() {{
    mkdir -p "$WORKDIR/agent/nexus_agent"
    : > "$WORKDIR/agent/requirements-agent.txt"
    printf 'print(%s)\\n' "'{{\\"node_id\\": \\"web-1\\", \\"api_key\\": \\"$NEW_KEY\\"}}'" > "$WORKDIR/agent/nexus_agent/__main__.py"
}}
"""


@pytest.fixture
def hostile_cwd(tmp_path_factory):
    hostile = tmp_path_factory.mktemp("hostile")
    for name in ("venv", "pip", "ensurepip", "secrets", "tarfile"):
        (hostile / f"{name}.py").write_text(f"open({str(hostile / 'RAN')!r}, 'a').write('{name}')\n")
    return hostile


def test_install_agent_from_a_hostile_cwd_runs_nothing_from_it(tmp_path, hostile_cwd):
    r = agent_shell(tmp_path, full_flow_lib(tmp_path) + f"cd {hostile_cwd}; main --token t --url https://n.example.com",
                    env={"NEW_KEY": "fresh"}, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REPORTED" in r.stdout
    assert not (hostile_cwd / "RAN").exists(), (hostile_cwd / "RAN").read_text()
    assert (tmp_path / "opt/venv/bin/python").exists()
    assert "NEXUS_API_KEY=fresh" in (tmp_path / "agent.env").read_text()


def test_token_is_ignored_with_a_notice_when_enrolled(tmp_path):
    env_file = tmp_path / "agent.env"
    env_file.write_text("NEXUS_URL=https://n.example.com\nNEXUS_API_KEY=kept\n")
    env_file.chmod(0o644)
    r = agent_shell(tmp_path, full_flow_lib(tmp_path) + "main --token SOMETOKEN", env={"NEW_KEY": "fresh"}, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "NEXUS_API_KEY=kept" in env_file.read_text()
    assert "token" in r.stdout.lower() and "ignored" in r.stdout.lower()
    assert "SOMETOKEN" not in r.stdout + r.stderr
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_no_token_no_notice_when_enrolled(tmp_path):
    (tmp_path / "agent.env").write_text("NEXUS_URL=https://n.example.com\nNEXUS_API_KEY=kept\n")
    r = agent_shell(tmp_path, full_flow_lib(tmp_path) + "main", env={"NEW_KEY": "fresh"}, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ignored" not in r.stdout.lower()


def test_re_enroll_replaces_the_key_and_keeps_other_settings(tmp_path):
    env_file = tmp_path / "agent.env"
    env_file.write_text(
        "NEXUS_URL=https://old.example.com\nNEXUS_API_KEY=old\nNEXUS_NODE_ID=old-node\n"
        "NEXUS_ALLOWLIST=10.0.0.1\nNEXUS_MAX_MODE=observe\n"
    )
    r = agent_shell(tmp_path, full_flow_lib(tmp_path) + "main --re-enroll --token t --url https://new.example.com",
                    env={"NEW_KEY": "fresh"}, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = env_file.read_text().splitlines()
    assert "NEXUS_API_KEY=fresh" in lines and "NEXUS_API_KEY=old" not in lines
    assert "NEXUS_URL=https://new.example.com" in lines and "NEXUS_URL=https://old.example.com" not in lines
    assert "NEXUS_NODE_ID=web-1" in lines and "NEXUS_NODE_ID=old-node" not in lines
    assert "NEXUS_ALLOWLIST=10.0.0.1" in lines
    assert lines.count("NEXUS_MAX_MODE=observe") == 1
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_re_enroll_needs_a_token(tmp_path):
    (tmp_path / "agent.env").write_text("NEXUS_URL=https://n.example.com\nNEXUS_API_KEY=old\n")
    r = agent_shell(tmp_path, "parse_args --re-enroll; resolve_target")
    assert r.returncode != 0 and "token" in r.stderr.lower()


def test_failed_re_enroll_keeps_the_old_key_and_install(tmp_path):
    env_file = tmp_path / "agent.env"
    env_file.write_text("NEXUS_URL=https://n.example.com\nNEXUS_API_KEY=old\n")
    r = agent_shell(
        tmp_path,
        full_flow_lib(tmp_path) + "main --re-enroll --token t",
        env={"NEW_KEY": "bad key with spaces"}, timeout=120,
    )
    assert r.returncode != 0
    assert env_file.read_text() == "NEXUS_URL=https://n.example.com\nNEXUS_API_KEY=old\n"
    assert (tmp_path / "opt/venv/bin/python").exists()
    assert not (tmp_path / "agent.env.tmp").exists()


def report_shell(tmp_path, state):
    (tmp_path / "state").mkdir()
    if state is not None:
        (tmp_path / "state" / "state.json").write_text(json.dumps(state))
    return agent_shell(tmp_path, 'URL=https://n.example.com; REPORT_WAIT=1; STARTED_AT=1000; PYTHON=python3; wait_for_report; report')


def test_report_says_reporting_only_after_a_send_since_start(tmp_path):
    r = report_shell(tmp_path, {"mode": "observe", "last_send": 1001})
    assert "reporting to https://n.example.com" in r.stdout and "not yet" not in r.stdout


@pytest.mark.parametrize("state", [None, {"mode": "observe"}, {"mode": "observe", "last_send": 999}, {"last_send": "x"}])
def test_report_does_not_claim_reporting_without_proof(tmp_path, state):
    r = report_shell(tmp_path, state)
    assert "service active, not yet reporting" in r.stdout.lower()
    assert "journalctl -u nexus-agent" in r.stdout


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
    cuts = {m.end() for m in re.finditer(rb"\n", body)} | set(range(len(body) - 20, len(body)))
    cuts -= {len(body), len(body) - 1}
    target = tmp_path / "cut.sh"
    for cut in sorted(cuts):
        target.write_bytes(body[:cut])
        r = subprocess.run(["/bin/bash", str(target)], env={"PATH": str(bin_dir)}, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, cwd=tmp_path, timeout=10)
        assert not log.exists(), f"{script} cut at byte {cut} ran {log.read_text()}"
        assert r.stdout == "", f"{script} cut at byte {cut} printed {r.stdout!r}"


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
    assert cfg["agent"]["omit_hostname"] is True
    probe = read("deploy/latency_probe.sh")
    assert defaults["cloudwatch_latency_namespace"].default in probe
    assert defaults["cloudwatch_latency_metric"].default in probe


def test_default_path_never_needs_aws():
    from backend.config import Settings

    assert Settings.model_fields["ingestion_source"].default == "webhook"
    assert "cloudwatch" not in read("install-agent.sh").lower()


def test_shellcheck_clean():
    assert shutil.which("shellcheck"), "shellcheck is not installed"
    files = ["install.sh", "install-agent.sh", "deploy/latency_probe.sh", "scripts/test.sh", "tests/e2e/install.sh", "tests/e2e/run.sh",
             "tests/e2e/check.sh"]
    r = subprocess.run(["shellcheck", "-x", *files], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
