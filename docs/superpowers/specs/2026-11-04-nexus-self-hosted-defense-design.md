# Nexus: Kendi Sunucuna Kurulan Saldırı Savunması

Tarih: 2026-11-04. Durum: onaylandı.

## Amaç

Nexus bugün sunucu metriklerinde anomali buluyor, ama README'nin vaat ettiği "saldırganı engelleme" işini yapamıyor. Elinde saldırgan bilgisi yok, engellediği IP de izlediği sunucunun kendisi. AWS kurulumuna da bağlı.

Hedef: Herkesin kendi Linux sunucularına kurabildiği, saldırganı kanıtla bulup engelleyen ve gerçek müşterileri engellemeyen bir ürün.

**En üst kural: Müşteriyi engellememek, saldırı kaçırmaktan önemlidir. Şüphede kalınırsa engellenmez.**

## Hedefler

- Tek komutla merkez kurulumu ve sunucu başına tek komutla agent kurulumu.
- AWS gerekmemesi. CloudWatch isteğe bağlı bir ek olur.
- Aşağıdaki kapsam tablosundaki saldırıların yakalanması.
- Bilinen tüm eksiklerin kapatılması (bkz. "Kapatılacak eksikler").
- README'nin yalnızca yapılabilen şeyleri anlatması.

## Kapsam

| Saldırı | Sinyal | Tepki |
|---|---|---|
| SSH şifre deneme | `auth.log`, `secure`, journald | Yalnızca SSH portunda IP engeli |
| Web login deneme | Web erişim logu | Yalnızca web portlarında IP engeli |
| Açık taraması (`/.env`, `/.git/config` gibi) | Web erişim logu | Yalnızca web portlarında IP engeli |
| Port taraması | Agent'ın nftables log kuralı | Alarm. Aynı IP'den el sıkışmayla kanıtlı kötü davranış da varsa tüm portlarda kısa engel |
| Bilinen web saldırı kalıpları (SQL injection, path traversal) | Web erişim logundaki URL | Yalnızca web portlarında IP engeli |
| Küçük ve orta DDoS (tek IP veya az sayıda IP) | IP başına bağlantı sayısı, SYN-RECV sayısı | Hız sınırı, tam engel yok |
| Büyük veya çok dağıtık DDoS | Trafik ve bağlantı sıçraması | Alarm ve Cloudflare önerisi, engel yok |
| Bilinmeyen şüpheli davranış | ML anomali skoru | Yalnızca alarm, hiçbir zaman engel yok |

## Kapsam dışı

- Barındırılan servis, üyelik, müşteri ayrımı, ödeme (sonraya bırakıldı).
- Virüs ve rootkit taraması, tam WAF, POST gövdesi incelemesi, yama yönetimi.
- Windows.
- Merkezler arası saldırgan listesi paylaşımı.

## Kaçınılacak sonuçlar

Teknik olarak çalışsa bile şunlar başarısızlık sayılır:
- Gerçek müşterilerin siteye erişememesi.
- Yöneticinin sunucusuna girememesi.
- Merkez ele geçirildiğinde, bağlı sunucularda komut çalıştırılabilmesi.
- Büyük DDoS'u durdurabildiğimizi iddia etmek.

## Yaklaşımlar

- **A) Mevcut Python kodunu genişletmek (seçildi):** Agent log okur ve yerel firewall'u yönetir, FastAPI merkez ve dashboard kalır. Çalışan kod ve testler korunur, müşteri koruma kuralları tamamen bizde olur. Eksisi, her sunucuda Python ortamı gerekmesi. Kurulum script'i bunu halleder.
- **B) Agent'ı Go ile yazmak:** Tek dosya kurulum ve düşük kaynak tüketimi sağlar. Yeni dil, yeni test ve derleme hattı gerektirir. Sonra geçilebilir.
- **C) CrowdSec veya fail2ban üstüne kurmak:** En az kodu bu gerektirir. Ek bağımlılık getirir ve müşteri koruma kurallarının uygulanabilirliği belirsizdir.

Kullanıcı, "en iyi, en hızlı, en güvenilir hangisiyse onu seç" dedi. A seçildi.

## Kullanıcının kararları

- Ürünü başkaları da kurup kullanacak.
- Herkes kendi sunucusuna kuracak. Barındırılan model sonraya kaldı.
- İlk öncelik DDoS ve genel hacker saldırıları.
- Kapsam tablosunun ilk hali kabul edildi.
- Müşteri IP'leri engellenmemeli. Bu, tasarımın en üst kuralı.
- Panel sıfırdan, açık tema, diğer projelerle aynı görsel dil.
- Tasarım 2026-11-04'te onaylandı.

## Mimari

```
Her korunan Linux sunucu                 Merkez (Docker Compose)
+--------------------------+   HTTPS     +----------------------------+
| nexus-agent              |  --------> | FastAPI + dashboard         |
|  toplayıcılar (log, ss)  |  metrik,    | ML anomali skoru            |
|  kural motoru            |  olay       | olay geçmişi, alarm         |
|  koruma listeleri        |  <-------- | sınırlı ayar ve komut kuyruğu|
|  nftables uygulayıcı     |  yanıtta    | Root yetkisi yok, firewall yok|
+--------------------------+  komut      +----------------------------+
```

**Tespit ve engelleme agent'ta çalışır.** Merkez kapalı olsa bile sunucu korunmaya devam eder. Agent, merkeze dışarı doğru bağlanır. Sunucularda port açılmaz.

**Merkez agent'a yalnızca sabit bir komut seti gönderebilir:** `unblock(ip)`, allowlist güncellemesi, mod değişikliği. Komut çalıştırma, dosya yazma veya uzaktan güncelleme yoktur. Merkezden uzaktan IP engelleme de yoktur. Komutlar ingest yanıtında taşınır.

**Yerel sınır:** Agent'ın `/etc/nexus-agent.env` dosyasındaki `NEXUS_MAX_MODE` değeri merkezden değiştirilemez. `observe` yapılırsa merkez o sunucuda engeli açamaz.

Modlar: `off`, `observe`, `enforce`. Mevcut `dry_run` adı `observe` olur.

## Müşteri koruma kuralları

Bu bölüm tasarımın zorunlu parçasıdır. Her kuralın testi olmalıdır.

**Hiçbir zaman engellenmeyenler:**
- Loopback, RFC1918, link-local, CGNAT (`100.64.0.0/10`) ve multicast adresleri.
- Kullanıcının allowlist'i.
- Merkezin IP'si ve varsayılan gateway.
- `/etc/resolv.conf` içindeki DNS sunucuları.
- Sunucuda aktif SSH oturumu olan IP'ler. Son 24 saatte başarılı SSH girişi yapan IP'ler de.
- Yayınlanmış CDN aralıkları: Cloudflare, Fastly, CloudFront. Pakete bir kopya gömülür, agent günde bir kez güncellemeyi dener. Güncelleme başarısızsa son liste kullanılmaya devam edilir.
- İleri ve geri DNS'i doğrulanan Googlebot ve Bingbot.

**Engelin dar tutulması:**
- Engel yalnızca saldırının geldiği porta uygulanır. Port taraması tek istisnadır, kısa süreli olur.
- Tam engel için log kanıtı gerekir. Skor veya trafik hacmi tek başına engel sebebi olmaz.
- Kapalı porta gelen SYN paketinin kaynağı sahte olabilir, bu yüzden tek başına kanıt sayılmaz. Tam engel için aynı IP'den tamamlanmış bağlantı gerektiren bir kanıt (SSH denemesi, web taraması, saldırı kalıbı, login denemesi) gerekir.
- Hacim temelli tepki yalnızca hız sınırıdır. NAT arkasındaki müşteriler aynı IP'yi paylaşabilir.
- IPv6'da engel `/64` bloğuna uygulanır.

**Güvenilir IP:** Son 1 saatte en az 20 başarılı (`2xx`/`3xx`) sayfa isteği yapıp hiç tarama izine rastlanmayan IP için web kurallarının ve `conn_flood` eşiği 3 katına çıkar. WordPress'te başarılı login (`/wp-login.php`'ye POST ve `302`) da güven sağlar. Diğer sitelerde durum kodu login'i kanıtlamaz, bu yüzden sayılmaz. SSH kurallarına web güveni uygulanmaz.

**Süre:** Engeller her zaman sürelidir ve süre kernelde tutulur (nftables set `timeout`). Agent çökse bile engel kendiliğinden biter. Tekrarlayan saldırıda süre katlanır, üst sınır 24 saattir.

**Devre kesici:** 5 dakikada 50'den fazla yeni engel oluşursa veya aktif engel sayısı 2000'i geçerse agent yeni tam engeli durdurur, alarm verir ve hız sınırına geçer. Bu hem yanlış kural hatasına hem de sahte kaynaklı saldırıya karşı korur.

**CDN veya proxy arkasında:** Firewall'da kaynak IP olarak CDN görünür, bu yüzden firewall engeli işe yaramaz ve tehlikelidir. Agent, trafik CDN aralıklarından geliyorsa o sunucudaki web kurallarını yalnızca alarm moduna alır. SSH kuralları çalışmaya devam eder. Gerçek IP için log ayarı dokümante edilir. Cloudflare API ile engel sonraki sürüme kalır.

**Log sahteciliği:** Saldırgan, kullanıcı adına veya URL'ye `from 8.8.8.8` gibi metin yazıp başkasını engelletmeye çalışabilir. Ayrıştırıcılar satırı sondan çapalar, IP'yi `ipaddress` ile doğrular ve logdaki `X-Forwarded-For` alanına yalnızca kullanıcı açıkça etkinleştirdiyse güvenir.

**Kurulum sonrası izleme:** Agent `observe` modunda başlar. 7 gün sonra dashboard "şu engelleri uygulardım" özetini gösterip `enforce` için onay ister. Otomatik geçiş olmaz. Kullanıcı isterse önce geçebilir.

## Tespit kuralları (varsayılan eşikler)

Eşikler 5 dakikalık kayan pencerede ve ayarlanabilirdir. Başlangıç değerleridir, gerçek trafikle ayarlanacaktır.

| Kural | Eşik | Engel süresi |
|---|---|---|
| `ssh_bruteforce` | 10 başarısız giriş | 1 saat |
| `web_login_bruteforce` | Login yollarına 30 `401`/`403` | 15 dakika |
| `web_probe` | Tarama listesinden 10 farklı yol ve `4xx` yanıt | 30 dakika |
| `web_exploit` | En az 2 ayrı istekte 3 farklı saldırı kalıbı | 1 saat |
| `port_scan` | 60 saniyede 20 farklı kapalı port | 15 dakika |
| `conn_flood` | IP başına 200 eşzamanlı bağlantı | Hız sınırı, 10 dakika |
| `distributed_flood` | SYN-RECV > 500 veya yeni bağlantıda ani sıçrama | Yalnızca alarm |

Login yolları ayarlanabilir, varsayılan `/login`, `/wp-login.php`, `/admin`, `/api/login`.

## Firewall

- **Yalnızca nftables:** Ubuntu 20.04+, Debian 11+, RHEL/Alma/Rocky 8+ destekli (Python 3.9+ gerekir; Ubuntu 20.04 ve RHEL 8 ailesinde `python3.9` paketi ayrıca kurulur). `nft` yoksa agent `observe` modunda kalır ve uyarı verir.
- **Kendi tablosu:** Tüm kurallar `inet nexus` tablosunda olur, kullanıcının kurallarına dokunulmaz. Kaldırmak için tablo silinir.
- **Docker uyumu:** Kurallar `prerouting` hook'unda, DNAT'tan önce (priority `-150`, conntrack'ten sonra ve DNAT'ın `-100` önceliğinden önce) çalışır. `input` zinciri Docker'ın yayınladığı portları görmez.
- **Set yapısı:** Porta göre engel, tüm portlarda kısa engel ve hız sınırı için `timeout` destekli ayrı setler (IPv4 ve IPv6).
- **Güvenli çağrı:** Komutlar shell olmadan, argv listesi olarak çalışır. IP doğrulaması mevcut `firewall_commands` yapısındaki gibi korunur.

## Agent

- **Paket:** `agent.py` yerine `nexus_agent/` paketi: `collectors`, `rules`, `protect`, `enforcer`, `client`, `main`.
- **Bağımlılık:** `psutil` ve `requests` dışında yeni bağımlılık yok. Python 3.9+.
- **Yetki:** Root olmayan kullanıcı, systemd ile `AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH`. Mevcut sıkılaştırma (`NoNewPrivileges`, `ProtectSystem=strict`) korunur. `nft` bu yetkilerle çalışmazsa root olarak çalışıp `CapabilityBoundingSet` ile sınırlamak yedek plandır.
- **Log okuma:** Dosya takibi log döndürmeye dayanıklıdır, journald için `journalctl -f` kullanılır. Nginx ve Apache `combined` formatı desteklenir. Ek dosyalar ayarla verilir.
- **Merkeze ulaşamazsa:** Son ayarlarla çalışmaya devam eder, olayları sınırlı bir bellek kuyruğunda tutar. Taşarsa en eskisini atar.
- **Bağlantı:** Merkez adresi `https` değilse agent reddeder. İstisna: loopback adresi veya açık `--insecure` bayrağı.
- **Desteklenmeyen sistemler:** macOS'ta agent yalnızca metrik gönderir, engel uygulamaz.

## Merkez

**Yeni API:**
- `POST /api/ingest`: Metrik ve güvenlik olayları, yanıtta bekleyen komutlar.
- `POST /api/agents/enroll`: Tek kullanımlık token karşılığında sunucu kaydı.
- `GET`/`POST` yönetim uçları: sunucu listesi, token üretme, sunucuyu iptal etme, mod ve allowlist.

**Kimlik:**
- `INGEST_API_KEY` yerine sunucu başına anahtar. Veritabanında hash olarak tutulur.
- Anahtar `node_id`'ye bağlıdır. Bir sunucu başkası adına veri gönderemez. Tek sunucu iptal edilebilir.
- Dashboard şifresi zorunludur. Tanımlı değilse uygulama açılmaz (`fail closed`). `/healthz` ve agent uçları dışındaki her şey korunur.
- Durum değiştiren isteklerde `Origin` kontrolü yapılır (CSRF koruması, çünkü Basic Auth tarayıcıda otomatik gönderilir).

**ML:**
- Transformer gerçekten devreye girer: `backend/main.py:119` ağırlığı geçer, `Weights` modeline eklenir, `.env.example` güncellenir, anomali kaydında skoru tutulur.
- Her sunucu için ayrı ölçekleme. Bugün tek `FeatureScaler` var, küçük ve büyük sunucu aynı ölçekte değerlendiriliyor. Her tür sunucuya kurulacak bir ürün için bu kabul edilemez.
- İlk eğitim veri yeterli olunca otomatik yapılır. Bugün ilk deneme 24 saat sonradır.
- `train()` yetersiz veride `SystemExit` atıyor ve çağıranlar yalnızca `Exception` yakalıyor. Bu arka plan görevinde süreci düşürebilir. Normal bir hata türüne çevrilir.

**Silinenler:**
- `SafeModeMiddleware` ve Safe Mode: Yalnızca Nexus'un kendi API'sini 503'e alıyor, korunan siteye bir faydası yok.
- Merkezdeki firewall kodu: Agent'a taşınır. `pfctl` ve `iptables` desteği kaldırılır.

**Sınır:** Varsayılan SQLite yaklaşık 50 sunucuya kadar öngörülmüştür (5 saniyelik aralıkla, ölçülmedi). Üstü için `DATABASE_URL` ile Postgres dokümante edilir, ilk sürümde sürücü imaja eklenir.

## Kurulum

**Merkez (`install.sh` yeniden yazılır):**
- AWS soruları kalkar. Docker otomatik kurulmaz: Yoksa kurulum net bir hatayla durur, çünkü başkasının sunucusunda paket deposu eklemek yan etki yaratır.
- Dashboard şifresi ve gizli anahtarlar üretilir, `.env` `chmod 600` olur.
- Alan adı verilirse Caddy ile HTTPS açılır, `TRUST_PROXY_HEADERS=true` olur, uygulama yalnızca iç ağda dinler. Bugünkü compose'ta Caddy ve `nexus` 80. portta çakışır, bu düzeltilir.
- Alan adı yoksa yalnızca `127.0.0.1` üzerinde dinler ve dashboard'a SSH tüneli ile girilir. Bu modda yalnızca aynı makinedeki agent bağlanır. Şifre internette düz HTTP'den gitmez.
- Kurulum sonunda dashboard adresi, kullanıcı adı ve şifre gösterilir.

**Agent:** Dashboard, sunucu başına komut üretir. `curl -fsSL https://<merkez>/install-agent.sh | sudo bash -s -- --token <tek-kullanımlık>`. Script merkezden sunulur, venv kurar, `systemd` servisini başlatır, `observe` modunda açılır. `--uninstall` agent'ı ve `inet nexus` tablosunu siler.

## Dashboard

Panel sıfırdan yeniden tasarlanır. Kullanıcı kararı: açık tema, kullanıcının diğer projeleriyle aynı görsel dil. Referans: `eminvo/apps/web/app/globals.css`.

**Görsel dil:**
- Açık tema tek tema. Mevcut koyu tema ve tema düğmesi kalkar.
- Renkler: zemin `#F4F4F1`, kart `#FFFFFF`, metin `#141518`, ikincil metin `#55575D`, çizgi `#D6D6D0`, birincil düğme `#141518`, başarılı `#257D4B` / `#DDF0E4`, tehlike `#B3261E` / `#FBE3E1`.
- Yazı tipi: Archivo (variable), pakete gömülür, CDN yok. Köşe: kart `12px`, form `10px`.
- Renk yalnızca durum için kullanılır: yeşil korunuyor, kırmızı aktif saldırı veya engel, kehribar izleme modu. Gradient, cam efekti ve neon yok.
- Kompakt yönetim paneli: sol kenar menü, geniş ekranda tablo ağırlıklı, telefonda tek kolon.
- Erişilebilirlik: WCAG AA kontrast, klavye ile kullanım, durum yalnızca renkle anlatılmaz.

**Sayfalar:**
- **Genel bakış:** Korunma durumu, son 24 saatte engellenen saldırı sayısı, dikkat gerektiren sunucular, son olaylar.
- **Sunucular:** Liste, durum, CPU/RAM/ağ/gecikme grafikleri ve anomali skoru. Sunucu ekleme (kurulum komutu üretir) ve iptal.
- **Engeller:** Aktif engel ve hız sınırları (sunucu, kural, kanıt, kalan süre), tek tıkla kaldırma.
- **İzleme:** `observe` modunda "şunu engellerdim" listesi, IP için "bu müşteri" ile allowlist'e ekleme, `enforce` geçiş onayı.
- **Olaylar:** Filtrelenebilir olay akışı (kural, kanıt satırı, ML anomalileri).
- **Ayarlar:** Allowlist ve mod düzenlenir. Eşikler agent'ın ayar dosyasında, Slack merkezin `.env` dosyasında kalır, panel bunları yalnızca gösterir. Böylece merkezin sabit komut seti genişlemez.

**Teknik:** Mevcut düz JS + vendored Chart.js korunur, framework ve build adımı eklenmez. `index.html`, `style.css`, `app.js` yeniden yazılır, gerekirse sayfa başına modüllere bölünür. Safe Mode arayüzü kaldırılır. Arayüz dili İngilizce kalır.

## CloudWatch

İsteğe bağlı metrik kaynağı olarak kalır, `INGESTION_SOURCE=webhook` varsayılan olur. Bu modda ML ve alarm çalışır, IP tespiti ve engel yoktur. Bunu dokümanda açıkça söyleriz.

## Kapatılacak eksikler

- Yanlış IP engeli ve CloudWatch'ta IP olmaması (agent mimarisiyle çözülür).
- Transformer ağırlığı.
- Şifresiz dashboard ve korumasız yönetim API'leri.
- `enforce` modunun Docker'da çalışmaması (engel artık agent'ta).
- Eksik `deploy/cloudwatch-agent.json` ve `deploy/latency_probe.sh` eklenir.
- `.env.example`: `mock` kaldırılır, yeni ayarlar eklenir.
- README baştan yazılır: `YOUR_USERNAME` düzeltilir, "Production Ready" ve DDoS iddiaları gerçeğe çekilir, sınırlar yazılır.
- `LICENSE` dosyası eklenir (README MIT diyor, dosya yok).
- Basit bir `SECURITY.md` eklenir.
- CI: Yeni testler ve nftables entegrasyon testi eklenir.

## Doğrulama

Bitmiş sayılması için:
1. **Birim testleri:** Her log ayrıştırıcı, gerçek log örnekleri ve sahtecilik denemeleriyle test edilir. Her kural eşik altı ve üstünde, her koruma kuralı ayrı test edilir.
2. **Firewall entegrasyonu:** `NET_ADMIN` yetkili Linux container'da gerçek `nft` ile engel, süre dolumu, port kapsamı ve kaldırma test edilir.
3. **Uçtan uca senaryo (Docker Compose):** Saldırgan ve müşteri container'ları aynı hedefe gider:
   - SSH deneyen saldırgan engellenir, aynı IP'den web çalışmaya devam eder.
   - Web tarayan saldırgan engellenir, müşteri container'ı aynı anda hiç hata almaz.
   - Çok istek atan tek IP (NAT benzetimi) tam engel yemez, hız sınırı alır.
   - CDN aralığından gelen trafik engellenmez.
   - Agent durdurulunca engel kernelde süresi dolunca kalkar.
   - Merkez kapalıyken agent engellemeye devam eder.
4. **Temiz kurulum:** Ubuntu 24.04 ve bir RHEL ailesi sistemde kurulum script'leri çalıştırılır. Mümkünse gerçek VM, olmazsa systemd içeren container. Hangisinin yapıldığı açıkça raporlanır.

Gerçek ortamdaki müşteri trafiğinde eşikler test edilmeden `enforce` önerilmez. Bu nedenle `observe` varsayılandır.

## Builder'a bırakılanlar

- Tarama yolu listesi ve saldırı kalıplarının içeriği.
- Veritabanı şeması ayrıntıları ve şema geçişi. Bilinen bir kurulu kullanıcı yok, basit geçiş yeterli.
- Ayar dosyası formatı, olay kuyruğu boyutu, sayfa içi yerleşim ayrıntıları.
- Sunucu başına ölçeklemenin uygulama biçimi.

## Bu belgede verilen, kullanıcıya sorulmamış kararlar

- `iptables` ve `pfctl` desteğinin kaldırılması. Konuşmadaki "macOS `pfctl` kodu kalır" önerisinden sapma: Port kapsamı ve kernelde süre için tek firewall'a inmek daha güvenilir.
- Safe Mode'un silinmesi.
- `enforce`'a geçişin 7 gün sonra otomatik değil onayla olması.
- Tam engel yerine hız sınırı ve port kapsamı.
- Web login denemesinde, konuşulan "IP'yi engeller" tepkisinin yalnızca web portlarıyla sınırlanması.
- CDN arkasında web kurallarının yalnızca alarm vermesi.
- Sunucu başına anahtar, `INGEST_API_KEY`'in kaldırılması.
- Alan adı yoksa yalnızca localhost modu.
- Eşik değerleri.
- Panelin tek tema olması ve arayüz dilinin İngilizce kalması.
