# Nexus Self-Hosted Defense Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Nexus'u herkesin kendi Linux sunucularına kurabildiği, saldırganı log kanıtıyla bulup engelleyen ve müşterileri engellemeyen bir ürüne çevirmek; paneli açık temayla sıfırdan yazmak.

**Architecture:** Tespit ve engelleme yeni `nexus_agent/` paketine taşınır, her sunucuda çalışır ve nftables'ı yönetir. Merkez (FastAPI, Docker Compose) root'suz kalır: metrik ve olay toplar, ML ile alarm üretir, agent'lara ingest yanıtında yalnızca `unblock`, `allowlist`, `mode` komutlarını gönderir. ML hiçbir zaman engel tetiklemez.

**Tech Stack:** Python 3.12 (merkez), Python 3.9+ uyumlu agent (`psutil`, `requests`), FastAPI, SQLAlchemy, PyTorch, nftables, Docker Compose, Caddy, düz JS + vendored Chart.js.

**Spec:** `docs/superpowers/specs/2026-11-04-nexus-self-hosted-defense-design.md`. Uygulayıcılar spec'i de okur.

## Global Constraints

- En üst kural: şüphede kalınırsa engellenmez. Skor veya trafik hacmi tek başına tam engel sebebi olamaz.
- Agent bağımlılığı yalnızca `psutil` ve `requests`; kod Python 3.9'da çalışır (`from __future__ import annotations`, `match` yok).
- Firewall yalnızca nftables, tablo `inet nexus`, hook `prerouting` priority `-150`. Komutlar argv listesi, shell yok.
- Modlar: `off`, `observe`, `enforce`. Varsayılan `observe`. `NEXUS_MAX_MODE` merkezden değiştirilemez.
- Merkez komut seti tam olarak: `unblock`, `allowlist`, `mode`.
- Her engel kernelde `timeout` ile tutulur; üst sınır 86400 saniye; kalıcı engel yok.
- Frontend'de framework, build adımı, CDN yok. Renkler spec'teki değerlerle birebir.
- Tüm kod ve arayüz metni İngilizce.
- Testler Docker'da Python 3.12 ile çalışır (`scripts/test.sh`), yerel Python 3.15 kullanılmaz.
- Çalışma `feature/self-hosted-defense` dalında; `main`'e push yok.
- Kod yorumu yalnızca kodun gösteremediği sebep için.

## Review Focus

1. Logda `::ffff:203.0.113.5` görünen IPv4-mapped adres, allowlist ve korumayı atlatmamalı; IPv4 olarak normalize edilmeli (Task 6).
2. Log döndürme (`logrotate` rename ve `copytruncate`) sırasında tail satır kaçırmamalı, eski dosyaya takılmamalı; bozuk UTF-8 veya çok uzun satır agent'ı düşürmemeli (Task 10).
3. Agent yeniden başlayınca mevcut `inet nexus` tablosu ve aktif engeller korunmalı; aynı kural tekrar `File exists` hatasıyla patlamamalı (Task 9).
4. Bir IP allowlist'e eklendiğinde o IP'nin mevcut engeli hemen kalkmalı; sürenin dolması beklenmemeli (Task 10).
5. Agent saati yanlışsa (ileri veya geri) merkez metrik zamanını güvenle işlemeli; 24 saatten fazla sapan zaman yerine sunucu zamanı kullanılmalı (Task 4).

---

### Task 1: Test altyapısı ve merkez hataları

**Files:**
- Create: `Dockerfile.test`, `scripts/test.sh`, `tests/test_ensemble_weights.py`, `tests/test_train_errors.py`
- Modify: `backend/main.py` (ensemble ağırlıkları, `Weights`, retrain döngüsü), `backend/pipeline.py:184-199`, `backend/db.py` (`Anomaly.transformer_score`), `training/train.py:101-104,118`, `.env.example`, `frontend` değişmez

**Interfaces:**
- Produces: `scripts/test.sh [pytest args]`; `training.train.NotEnoughDataError(Exception)`; `Ensemble` tüm dört ağırlığı alır.

- [ ] **Step 1:** `git switch -c feature/self-hosted-defense`. `Dockerfile.test` (python:3.12-slim, CPU torch, `requirements-dev.txt`, `psutil`, `requests`) ve kaynak kodu mount edip pytest çalıştıran `scripts/test.sh` yaz. Çalıştır: `scripts/test.sh`. Beklenen: mevcut testler geçer; geçmeyen varsa sonucu not et, sonra başla.
- [ ] **Step 2: Failing testler**

```python
def test_transformer_weight_from_settings():
    assert build_ensemble(settings).weights["transformer"] > 0

def test_train_raises_catchable_error_when_data_is_short():
    with pytest.raises(NotEnoughDataError):
        train(short_data, 12, 1, 500, 42, "test")

async def test_retrain_loop_survives_short_data(): ...  # döngü bir tur sonra hâlâ çalışır, process düşmez
```

- [ ] **Step 3:** Fail olduğunu doğrula: `scripts/test.sh tests/test_ensemble_weights.py tests/test_train_errors.py`
- [ ] **Step 4:** `build_ensemble(settings) -> Ensemble` ekle ve `weight_transformer` geçir. `Weights` modeline `transformer` ekle. `train()` ve CLI: kütüphane `NotEnoughDataError` atar, yalnızca `main()` onu `SystemExit`'e çevirir. Anomaliye `transformer_score` kolonu (mevcut `init_db` geçiş kalıbıyla). `.env.example`: `mock` kaldır, `WEIGHT_TRANSFORMER=0.30` ekle.
- [ ] **Step 5:** `_continuous_learning`: ilk uyku 86400 yerine saatlik deneme; model yokken her saat, model varken 24 saatte bir eğit. `NotEnoughDataError` info logu olur. Testi çalıştır, geçmeli.
- [ ] **Step 6:** Commit: `fix: enable transformer weight and survive short training data`

### Task 2: Merkez kimlik doğrulaması

**Files:**
- Modify: `backend/config.py`, `backend/main.py`, `backend/security.py`, `tests/conftest.py`, `tests/test_api.py`
- Test: `tests/test_auth_required.py`

**Interfaces:**
- Produces: `backend.config.Settings.require_dashboard_credentials() -> None` (eksikse `RuntimeError`); `backend.security.OriginCheckMiddleware(app, trust_proxy)`.

- [ ] **Step 1: Failing testler**

```python
def test_app_refuses_to_start_without_password(): 
    with pytest.raises(RuntimeError): Settings(dashboard_password="").require_dashboard_credentials()

@pytest.mark.parametrize("method,path", [("POST","/api/retrain"),("POST","/api/weights"),("GET","/api/agents"),("GET","/metrics")])
def test_admin_routes_require_auth(client, method, path):
    assert client.request(method, path).status_code == 401

def test_cross_origin_post_rejected(authed):
    assert authed.post("/api/weights", json=W, headers={"Origin":"https://evil.example"}).status_code == 403
```

- [ ] **Step 2:** `scripts/test.sh tests/test_auth_required.py`, fail bekle.
- [ ] **Step 3:** Lifespan başında `require_dashboard_credentials()`. Basic auth her zaman eklenir; muaf yollar `/healthz`, `/api/ingest`, `/api/agents/enroll`, `/install-agent.sh`. `OriginCheckMiddleware`: `POST/PUT/PATCH/DELETE` isteğinde `Origin` varsa ve host ile eşleşmiyorsa 403; `Origin` yoksa geçer (agent ve curl).
- [ ] **Step 4:** Test geçmeli. Tüm testleri çalıştır, `conftest.py` test şifresi set etsin.
- [ ] **Step 5:** Commit: `feat: require dashboard credentials and reject cross-origin writes`

### Task 3: Sunucu kaydı ve sunucu başına anahtar

**Files:**
- Create: `backend/agents.py`, `tests/test_enroll.py`
- Modify: `backend/db.py` (`Agent`, `EnrollToken`), `backend/main.py`, `backend/config.py`, `backend/security.py` (`ApiKeyMiddleware` silinir), `.env.example`, `docker-compose.yml` (agent profili silinir)

**Interfaces:**
- Produces: `create_enroll_token(db, name: str, ttl: int = 86400) -> str`; `enroll(db, token: str, hostname: str) -> tuple[str, str]` `(node_id, api_key)`; `authenticate(db, api_key: str) -> Agent | None`; `revoke(db, node_id: str) -> bool`. Anahtar ve token SHA-256 hash olarak tutulur. `require_agent` FastAPI dependency.
- `Agent` kolonları: `node_id` PK, `name`, `key_hash`, `created_at`, `first_seen`, `last_seen`, `revoked_at`, `mode`, `max_mode`, `version`, `capabilities` JSON, `config` JSON, `allowlist` JSON.

- [ ] **Step 1: Failing testler**

```python
def test_token_is_single_use(): # ikinci enroll 401
def test_expired_token_rejected(): ...
def test_ingest_requires_valid_key(): # anahtarsız ve yanlış anahtar 401
def test_key_cannot_write_other_node(): # payload node_id başka agent ise 403
def test_revoked_agent_rejected(): ...
def test_key_never_stored_plain(): assert key not in db_dump
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** `backend/agents.py` yaz. `POST /api/agents/enroll`, `POST /api/agents/tokens`, `GET /api/agents`, `DELETE /api/agents/{node_id}`. Ingest `require_agent` kullanır. `INGEST_API_KEY` ayarı ve middleware silinir. Karşılaştırma `secrets.compare_digest`.
- [ ] **Step 4:** Test geçmeli.
- [ ] **Step 5:** Commit: `feat: per-server enrollment and API keys`

### Task 4: Ingest v2, olaylar, komut kuyruğu, savunma kodunun silinmesi

**Files:**
- Create: `backend/commands.py`, `tests/test_ingest_v2.py`
- Modify: `backend/main.py`, `backend/pipeline.py`, `backend/db.py` (`SecurityEvent`, `AgentCommand`; `DefenseEvent` kaldır), `backend/metrics.py`, `frontend` geçici kırık kalabilir (Task 12 yeniden yazar)
- Delete: `backend/defense.py`, `tests/test_defense.py`, `tests/test_pipeline_defense.py` (firewall testleri Task 9'da yeniden yazılır)

**Interfaces:**
- Ingest isteği: `{timestamp, cpu_pct, memory_pct, net_kbps, latency_ms, events: [SecurityEventIn], active_blocks: [BlockIn], version, capabilities, config}`. Yanıt: `{status, commands: [{id, type, payload}], acked: bool}`. İstek `acked_commands: [int]` taşır.
- `SecurityEventIn`: `rule, ip, action, ports, ttl, evidence (max 500), simulated, ok, ts`.
- `enqueue(db, node_id, type: Literal["unblock","allowlist","mode"], payload: dict) -> int`; `pending(db, node_id) -> list[dict]`; `ack(db, node_id, ids: list[int]) -> None`. Başka tip `ValueError`.
- `POST /api/agents/{node_id}/unblock`, `PUT .../allowlist`, `PUT .../mode` (mode `max_mode`'u aşarsa 409). `GET /api/events?node=&rule=&action=&simulated=&limit=`, `GET /api/blocks`.

- [ ] **Step 1: Failing testler**

```python
def test_only_three_command_types(): 
    with pytest.raises(ValueError): enqueue(db, "n", "exec", {})

def test_commands_delivered_until_acked(): ...
def test_mode_above_max_rejected(): assert r.status_code == 409
def test_ml_anomaly_never_creates_block(): # kritik skorlu metrik sonrası komut kuyruğu boş, block olayı yok
def test_timestamp_skew_uses_server_time(): # 2 gün ileri timestamp -> Metric.ts server zamanına yakın
def test_evidence_truncated_and_ip_validated(): # geçersiz ip 422
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** Şemaları ve uçları yaz. `Pipeline`den `defender`, `node_ips`, `source_ip` çıkar. `SafeModeMiddleware`, `ActiveDefender`, `DEFENSE_*` ayarları silinir. `abs(timestamp-now) > 86400` ise sunucu zamanı. Kritik anomali yalnızca Slack ve WebSocket yayını yapar. `events` Slack'e kritik kural olarak iletilir (`SlackNotifier` yeniden kullanılır).
- [ ] **Step 4:** Tüm testleri çalıştır; geçmeli.
- [ ] **Step 5:** Commit: `feat: ingest security events and queue limited agent commands`

### Task 5: Sunucu başına ölçekleme

**Files:**
- Modify: `training/train.py`, `backend/models/ensemble.py` (`BUNDLE_FORMAT = 2`), `backend/models/features.py`, `backend/pipeline.py`
- Test: `tests/test_per_node_scaling.py`

**Interfaces:**
- Bundle `scalers: dict[str, dict]` ve `default_scaler` taşır. `Ensemble.predict` ilgili node scaler'ını, yoksa `default_scaler`'ı kullanır. Eski format bundle reddedilir ve eğitime dönülür (mevcut `load` hatası zaten learning moduna düşürür).

- [ ] **Step 1: Failing test**

```python
def test_big_server_normal_load_is_not_anomalous_because_of_small_server():
    # küçük sunucu net=10, büyük sunucu net=10000 ile eğitilir
    assert ens.predict("big", normal_big).ensemble < ens.threshold

def test_unknown_node_uses_default_scaler(): assert ens.predict("new", row) is not None
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** Her node için `FeatureScaler.fit`, 50 satırdan az verisi olan node `default_scaler` kullanır. `culprit` ve `contributions` node ölçeğiyle hesaplanır.
- [ ] **Step 4:** Test geçmeli.
- [ ] **Step 5:** Commit: `feat: scale metrics per server`

### Task 6: Log ayrıştırıcılar

**Files:**
- Create: `nexus_agent/__init__.py`, `nexus_agent/parsers.py`, `tests/agent/test_parsers.py`, `tests/agent/fixtures/` (gerçek `auth.log`, `secure`, nginx ve apache örnekleri)

**Interfaces:**
- Produces: `normalize_ip(s: str) -> str | None`; `LogEvent(kind: "ssh_fail"|"ssh_ok"|"web", ip, ts, method=None, path=None, status=None, raw="")`; `parse_ssh_line(line, now) -> LogEvent | None`; `parse_web_line(line, now) -> LogEvent | None`. `raw` en fazla 300 karakter.

- [ ] **Step 1: Failing testler**

```python
def test_username_injection_uses_real_ip():
    line = "sshd[1]: Failed password for invalid user x from 8.8.8.8 port 1 from 203.0.113.9 port 22 ssh2"
    assert parse_ssh_line(line, 0).ip == "203.0.113.9"

def test_url_injection_ignored():
    assert parse_web_line('198.51.100.7 - - [t] "GET /a?x=1.1.1.1 HTTP/1.1" 404 1 "-" "1.1.1.1"', 0).ip == "198.51.100.7"

def test_ipv4_mapped_normalized(): assert normalize_ip("::ffff:203.0.113.5") == "203.0.113.5"
def test_invalid_ip_returns_none(): assert normalize_ip("999.1.1.1") is None
def test_garbage_line_returns_none(): assert parse_web_line("\x00\xff" * 5000, 0) is None
def test_accepted_login_is_ssh_ok(): ...
```

- [ ] **Step 2:** Fail doğrula: `scripts/test.sh tests/agent/test_parsers.py`
- [ ] **Step 3:** SSH regex satır sonuna çapalı (`from <ip> port \d+( ssh2)?$`). Web regex satır başına çapalı. 16 KB üstü satır `None`. `path` sorgu dizesi dahil saklanır.
- [ ] **Step 4:** Test geçmeli.
- [ ] **Step 5:** Commit: `feat(agent): parse ssh and web logs safely`

### Task 7: Koruma listeleri ve güvenilir IP

**Files:**
- Create: `nexus_agent/protect.py`, `nexus_agent/data/cdn_ranges.json`, `tests/agent/test_protect.py`

**Interfaces:**
- Produces: `Protector(allowlist, central_ip, gateway, resolvers, clock, resolver=socket)`; `reason(ip) -> str | None`; `note_ssh_ok(ip)`; `note_web(event)`; `note_probe(ip)`; `set_active_ssh(ips)`; `set_allowlist(items)`; `threshold_multiplier(ip) -> int` (1 veya 3); `is_cdn(ip) -> bool`; `verify_bot(ip, user_agent) -> bool`; `refresh_cdn_ranges() -> bool`.

- [ ] **Step 1: Failing testler**

```python
@pytest.mark.parametrize("ip", ["127.0.0.1","10.0.0.1","192.168.1.1","100.64.0.1","fe80::1","224.0.0.1"])
def test_special_ranges_protected(p, ip): assert p.reason(ip)

def test_cloudflare_protected(p): assert p.reason("104.16.0.1") == "cdn"
def test_active_ssh_protected(p): p.set_active_ssh(["203.0.113.1"]); assert p.reason("203.0.113.1")
def test_ssh_success_protected_for_24h(p, clock): ...  # 23s evet, 25s hayır
def test_trusted_after_20_ok_requests(p): assert p.threshold_multiplier(ip) == 3
def test_probe_removes_trust(p): ...
def test_googlebot_forward_confirmed_only(p): # sahte rDNS reddedilir
def test_cdn_refresh_failure_keeps_list(p): ...
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** Yaz. `cdn_ranges.json`: Cloudflare, Fastly, CloudFront yayınlanmış listeleri (yazım sırasında resmi URL'lerden indirilir, URL'ler dosyada kayıtlı). Bot doğrulaması kural eşiği aşıldığında çağrılır, sonuç 1 saat önbelleklenir, zaman aşımı 2 saniye, başarısızlık "doğrulanmadı" sayılır.
- [ ] **Step 4:** Test geçmeli.
- [ ] **Step 5:** Commit: `feat(agent): never block protected addresses`

### Task 8: Kural motoru

**Files:**
- Create: `nexus_agent/rules.py`, `nexus_agent/data/probe_paths.txt`, `nexus_agent/data/exploit_patterns.txt`, `tests/agent/test_rules.py`

**Interfaces:**
- Consumes: `LogEvent`, `Protector`.
- Produces: `Decision(rule, ip, action: "block_port"|"block_all"|"rate_limit"|"alert", ports: tuple[int,...], ttl: int, evidence: str)`; `RuleConfig` (spec'teki eşikler varsayılan, `login_paths`, `ssh_ports`, `web_ports`); `RuleEngine(cfg, protector, clock)`; `feed(event) -> list[Decision]`; `feed_connections(per_ip: dict[str,int], syn_recv: int) -> list[Decision]`; `feed_scan(ip, port) -> list[Decision]`.

- [ ] **Step 1: Failing testler** (her kural için eşik altı boş, eşikte tek karar)

```python
def test_ssh_9_fails_no_block(): ...
def test_ssh_10_fails_blocks_ssh_port_only():
    d = feed_n(engine, ssh_fail(IP), 10)[-1]
    assert (d.rule, d.action, d.ports, d.ttl) == ("ssh_bruteforce","block_port",(22,),3600)

def test_web_login_30_fails_blocks_web_ports_15m(): ...
def test_web_probe_10_distinct_paths_30m(): ...  # aynı yolu 100 kez = engel yok
def test_probe_with_200_status_not_counted(): ...  # sitede gerçekten var
def test_web_exploit_3_distinct_patterns_1h(): ...
def test_port_scan_20_ports_60s_all_ports_15m(): ...
def test_conn_flood_rate_limits_not_blocks(): assert d.action == "rate_limit" and d.ttl == 600
def test_distributed_flood_alert_only(): assert d.action == "alert"
def test_trusted_ip_threshold_tripled(): ...
def test_protected_ip_produces_no_block(): ...
def test_repeat_offender_ttl_doubles_capped_86400(): ...
def test_cdn_source_web_rules_alert_only_ssh_still_blocks(): ...
def test_no_duplicate_decision_while_active(): ...
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** IP başına `deque` kayan pencere; bellek sınırı 100000 IP, en eski atılır. Karar öncesi `protector.reason`. Korumalı IP için karar yerine `action="alert"` üretilmez, sessiz sayılır ve sayaç artar. Kanıt: son eşleşen `raw` satırları, 500 karakter.
- [ ] **Step 4:** Test geçmeli.
- [ ] **Step 5:** Commit: `feat(agent): detection rules with customer-safe thresholds`

### Task 9: nftables uygulayıcı

**Files:**
- Create: `nexus_agent/enforcer.py`, `tests/agent/test_enforcer.py`, `tests/agent/test_enforcer_nft.py`, `Dockerfile.nft-test`
- Modify: `scripts/test.sh` (`--nft` bayrağı: `--cap-add=NET_ADMIN` ile entegrasyon)

**Interfaces:**
- Consumes: `Decision`.
- Produces: `Enforcer(mode, runner, clock, max_new_per_5m=50, max_active=2000)`; `setup() -> bool`; `apply(decision) -> ApplyResult(ok, simulated, detail)`; `remove(ip) -> bool`; `active() -> list[BlockIn]` (kernelden `nft -j list set` okur); `update_listening(ports)`; `set_mode(mode)`; `teardown()`; `breaker_open: bool`.
- Setler: `port4`/`port6` (`ipv4_addr . inet_service`), `all4`/`all6`, `limit4`/`limit6`, `listening` (`inet_service`); hepsi `flags timeout` (`listening` hariç). IPv6 `flags interval`, `/64` olarak yazılır.

- [ ] **Step 1: Failing birim testler** (sahte runner ile)

```python
async def test_observe_never_runs_nft(): assert runner.calls == []
async def test_block_port_argv_exact(): assert ["nft","add","element","inet","nexus","port4","{ 203.0.113.9 . 22 timeout 3600s }"] in runner.calls
async def test_ipv6_blocked_as_64(): ...
async def test_breaker_opens_after_50_in_5m(): # 51. tam engel uygulanmaz, rate_limit'e düşer, breaker_open True
async def test_invalid_ip_raises_before_exec(): ...
async def test_setup_idempotent(): ...  # iki kez setup hata vermez, kurallar çoğalmaz
async def test_file_exists_error_is_success(): ...
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** `setup` tablo varsa setleri korur: `nft -f` ile atomik `add table/set/chain`; kurallar yalnızca zincir boşsa eklenir. Kurallar: `ip saddr . tcp dport @port4 drop`, `ip saddr @all4 drop`, `ip saddr @limit4 ct state new limit rate over 50/second drop`, ayrıca log kuralı `ct state new tcp flags syn tcp dport != @listening limit rate 50/second log prefix "nexus-scan "`. Durum kernelden okunur.
- [ ] **Step 4:** Birim test geçmeli.
- [ ] **Step 5: Entegrasyon testi (gerçek nft)**

```python
def test_block_expires_in_kernel(): # ttl=2, 3 sn sonra set boş
def test_port_scope_really_scoped(): # 22 kapalı, 8080 açık (veth çiftiyle ağ namespace)
def test_restart_keeps_blocks(): # yeni Enforcer.setup sonrası active() aynı
def test_teardown_removes_table(): ...
```

Run: `scripts/test.sh --nft tests/agent/test_enforcer_nft.py`. Beklenen: PASS. Docker Desktop kernelinde nft yoksa bu sonuç açıkça raporlanır ve CI'da çalıştırılır.

- [ ] **Step 6:** Commit: `feat(agent): nftables enforcer with kernel timeouts and breaker`

### Task 10: Agent çalışma döngüsü

**Files:**
- Create: `nexus_agent/collectors.py`, `nexus_agent/client.py`, `nexus_agent/config.py`, `nexus_agent/main.py`, `nexus_agent/__main__.py`, `tests/agent/test_collectors.py`, `tests/agent/test_client.py`, `tests/agent/test_main_loop.py`
- Delete: `agent.py`, `requirements-agent.txt` içeriği `psutil`, `requests` olarak kalır

**Interfaces:**
- Consumes: `parsers`, `Protector`, `RuleEngine`, `Enforcer`.
- Produces: `FileTail(path).read_lines() -> list[str]` (rotate ve truncate farkındalığı, `errors="replace"`, başlangıçta dosya sonundan başlar); `JournalTail(args)`; `sample_metrics() -> dict`; `sample_connections() -> (per_ip, syn_recv, active_ssh, listening_ports)`; `Client(url, key, allow_insecure)`; `Client.send(payload) -> list[Command]`; `AgentConfig.from_env()`; `Agent.tick()`; `Agent.handle_command(cmd)`.

- [ ] **Step 1: Failing testler**

```python
def test_tail_follows_rename_rotation(tmp_path): ...
def test_tail_follows_copytruncate(tmp_path): ...
def test_tail_survives_invalid_utf8_and_missing_file(tmp_path): ...
def test_client_refuses_http_unless_loopback_or_insecure(): ...
def test_queue_bounded_drops_oldest_when_central_down(): ...
def test_blocks_continue_when_central_down(): ...
def test_max_mode_cannot_be_exceeded_by_command(): # max observe, mode=enforce komutu reddedilir
def test_unblock_command_removes(): ...
def test_allowlist_command_lifts_existing_block(): # enforcer.remove çağrılır
def test_unknown_command_ignored_and_logged(): ...
def test_metrics_keep_working_on_macos_without_nft(): # capabilities enforce=False, mode observe
def test_alert_from_observe_marks_simulated(): ...
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** Yaz. Döngü aralığı 5 sn; loglar 1 sn. Log yolları: `/var/log/auth.log`, `/var/log/secure`, yoksa `journalctl -u ssh -u sshd -f -o cat`; nginx ve apache varsayılan erişim logları, `NEXUS_WEB_LOGS` ek yollar. Kernel logu `journalctl -k -f`, `nexus-scan` prefix'i `SRC=` `DPT=` ayrıştırılır. Gateway `/proc/net/route`, resolver `/etc/resolv.conf`. Yapılandırma `/etc/nexus-agent.env`. Komutlar komut tipi dışında hiçbir şey çalıştırmaz.
- [ ] **Step 4:** Test geçmeli.
- [ ] **Step 5:** Commit: `feat(agent): collection loop, central client and limited commands`

### Task 11: Kurulum ve dağıtım

**Files:**
- Create: `install-agent.sh`, `deploy/cloudwatch-agent.json`, `deploy/latency_probe.sh`, `tests/test_install_scripts.py`
- Modify: `install.sh`, `docker-compose.yml`, `Dockerfile`, `deploy/systemd/nexus-agent.service`, `deploy/Caddyfile`, `backend/main.py` (`GET /install-agent.sh`, `GET /agent.tar.gz`), `.env.example`, `requirements.txt` (`psycopg[binary]`), `backend/config.py` (varsayılan `webhook`)
- Modify: `deploy/launchd/com.nexus.agent.plist` (macOS metrik modu için kalır, `python -m nexus_agent` çağırır)

**Interfaces:**
- Agent kurulumu: `curl -fsSL https://<merkez>/install-agent.sh | sudo bash -s -- --token <t>`; `--uninstall`. Sunucu `/etc/nexus-agent.env` (600) yazar, `nexus-agent` kullanıcısı oluşturur, `adm`/`systemd-journal` grubu ekler, `/opt/nexus-agent/venv` kurar.
- `install.sh --domain <d>` veya etkileşimli; alan adı yoksa `HTTP_BIND=127.0.0.1:8000`, `caddy` yok.

- [ ] **Step 1: Failing testler**

```python
def test_compose_nexus_has_no_public_port_with_domain(): ...  # parse yaml, 80 çakışması yok
def test_install_generates_password_and_mode_600(tmp_path): # stub docker ile çalıştır
def test_install_never_prompts_for_aws(): assert "AWS_ACCESS_KEY" not in read("install.sh")
def test_install_agent_endpoint_public_and_contains_no_secret(client): ...
def test_agent_tarball_excludes_backend(client): ...
def test_shellcheck_clean(): ...
```

- [ ] **Step 2:** Fail doğrula.
- [ ] **Step 3:** Yaz. Systemd: `AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH`, `CapabilityBoundingSet` aynı, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`. `Dockerfile` `nexus_agent` paketini sunabilmek için kopyalar. `DOMAIN` set edilince `TRUST_PROXY_HEADERS=true`. CloudWatch dosyaları mevcut `_HINTS` metrik adlarıyla (`mem_used_percent`, `Nexus/RequestLatency`) uyumlu yazılır.
- [ ] **Step 4:** Test geçmeli. `docker compose config` hata vermemeli.
- [ ] **Step 5:** Commit: `feat: self-hosted installers without AWS dependency`

### Task 12: Panel yeniden tasarım

**Files:**
- Rewrite: `frontend/index.html`, `frontend/style.css`, `frontend/app.js`
- Create: `frontend/fonts/archivo.woff2` (`../eminvo/apps/web/public/fonts/archivo.woff2` kopyası), `frontend/js/{api,overview,servers,blocks,watch,events,settings}.js` (`type="module"`), `tests/test_frontend_contract.py`, `tests/e2e/panel.spec.mjs`
- Modify: `frontend/logo.svg` (tek renk, `#141518`), `backend/main.py` (`GET /api/overview`, `GET /api/watch/{node_id}`, `Agent.config` görüntüleme)
- Delete: Koyu tema, `themeToggle`, Safe Mode, ağırlık düzenleme arayüzü, `assets/nexus_dashboard.jpg` (yeni ekran görüntüsüyle değişir)

**Interfaces:**
- Consumes: Task 3-4 API'leri. Sayfalar hash ile: `#/`, `#/servers`, `#/servers/:id`, `#/blocks`, `#/watch`, `#/events`, `#/settings`.
- Tokenlar (`:root`): `--bg:#F4F4F1; --surface:#FFFFFF; --fg:#141518; --muted:#55575D; --line:#D6D6D0; --btn-bg:#141518; --btn-fg:#FFFFFF; --ok:#257D4B; --ok-tint:#DDF0E4; --danger:#B3261E; --danger-tint:#FBE3E1; --warn:#8A5A00; --warn-tint:#FBF0D9; --r:12px`. `color-scheme: light` yalnızca.

- [ ] **Step 1:** `impeccable:impeccable` becerisini çalıştır; `Eminvo` görsel dilinden Nexus Genel Bakış tasarımını kısa önizle. Kullanıcıdan görsel onayı al.
- [ ] **Step 2: Failing kontrat testleri**

```python
def test_no_dark_theme_left(): assert "prefers-color-scheme: dark" not in css and "themeToggle" not in html
def test_no_external_urls(): assert not re.search(r'(src|href)="https?://', html)
def test_tokens_exact(): assert "--bg: #F4F4F1" in css
def test_no_safe_mode_references(): assert "safe" not in app_sources.lower()
def test_overview_shape(authed): assert {"protection","blocked_24h","attention","recent"} <= set(authed.get("/api/overview").json())
```

- [ ] **Step 3:** Fail doğrula.
- [ ] **Step 4:** Her sayfayı spec'e göre yaz. Log kaynaklı her değer (`evidence`, `ip`, `rule`) `textContent` veya mevcut `esc` ile basılır; saldırgan logu panelde XSS olamaz. Durum renk artı metinle. Sunucu ekleme ekranı tek kullanımlık komutu kopyalar. "Bu müşteri" allowlist komutu + unblock gönderir. `enforce` geçişi onay diyaloğu ve 7 günlük özetle. Yeni agent'ta `first_seen + 7 gün` dolunca Genel Bakış'ta çağrı görünür; otomatik geçiş yok. 900 px altı tek kolon, menü üstte.
- [ ] **Step 5: Tarayıcı testi** (`tests/e2e/panel.spec.mjs`, Playwright container, örnek veriyle): tüm sayfalar konsol hatasız açılır; `evidence` içine `<img src=x onerror=...>` konur ve çalışmaz; 375 px'te yatay kaydırma yok; klavye ile unblock yapılır; axe ile WCAG AA ihlali yok. Ekran görüntülerine bak.
- [ ] **Step 6:** Tüm testleri çalıştır. README için ekran görüntüsünü `assets/nexus_dashboard.png` olarak kaydet.
- [ ] **Step 7:** Commit: `feat(panel): rebuild dashboard with light theme`

### Task 13: Uçtan uca saldırı senaryoları

**Files:**
- Create: `tests/e2e/docker-compose.e2e.yml`, `tests/e2e/run.sh`, `tests/e2e/scenarios.py`

**Interfaces:**
- Consumes: Tüm sistem. Compose: `central`, `target` (systemd'siz, `NET_ADMIN`, nginx, sshd, agent `enforce`), `attacker`, `customer`, `nat_customer` (hepsi ayrı IP, aynı bridge). Bridge alt ağı `203.0.113.0/24` (TEST-NET-3) olur, böylece korumalı aralık kuralları kapatılmaz ve üründe test için bir atlatma ayarı bulunmaz.

- [ ] **Step 1:** Senaryoları yaz, sistem kurulmadan fail olduğunu gör:

```python
def test_ssh_attacker_blocked_on_22_but_web_still_works(): ...
def test_web_scanner_blocked_customer_sees_zero_errors(): ...
def test_high_volume_nat_ip_rate_limited_not_blocked(): ...
def test_cdn_source_never_blocked(): ...  # protect listesine test CIDR eklenir
def test_block_expires_with_agent_stopped(): ...
def test_blocks_continue_with_central_stopped(): ...
def test_panel_unblock_reaches_agent(): ...
def test_ml_critical_score_no_block(): ...
```

- [ ] **Step 2:** `tests/e2e/run.sh`. Beklenen: tüm senaryolar PASS. Bulunan hataları ilgili modülde düzelt.
- [ ] **Step 3:** Commit: `test: end-to-end attack and customer scenarios`

### Task 14: Doküman, lisans, CI, temiz kurulum

**Files:**
- Rewrite: `README.md`
- Create: `LICENSE` (MIT, `Copyright (c) 2026 Emin Aydin`), `SECURITY.md`, `docs/threshold-tuning.md`
- Modify: `.github/workflows/ci.yml`, `.env.example`, `.dockerignore`

- [ ] **Step 1:** README: Nexus ne yapar ve ne yapmaz; 2 adımda kurulum; kapsam tablosu; "Büyük DDoS'u durduramaz, Cloudflare kullanın" bölümü; CDN arkası davranış; müşteri koruma kuralları; `observe` → `enforce`; CloudWatch ekini; SQLite ve Postgres sınırı; agent yetkileri ve merkez ele geçirilirse neler olabilir. "Production Ready" rozeti, `YOUR_USERNAME` ve tüm AWS-only iddiaları kalkar.
- [ ] **Step 2:** CI: Birim testler, `--nft` entegrasyon, `shellcheck`, e2e. Commit'lemeden önce `act` yoksa dal push'unda koşacağı not edilir.
- [ ] **Step 3: Temiz kurulum.** Ubuntu 24.04 ve Rocky 9 üzerinde `install.sh` ve `install-agent.sh`. Gerçek VM yoksa systemd'li container. Beklenen: panel açılır, agent `observe` modunda görünür, `--uninstall` sonrası `nft list table inet nexus` hata verir. Hangi ortamda koştuğu sonuçla raporlanır.
- [ ] **Step 4:** `scripts/test.sh`, `scripts/test.sh --nft`, `tests/e2e/run.sh` hepsi çalıştırılır, çıktılar raporlanır.
- [ ] **Step 5:** Commit: `docs: rewrite README and add license, security policy and CI`
