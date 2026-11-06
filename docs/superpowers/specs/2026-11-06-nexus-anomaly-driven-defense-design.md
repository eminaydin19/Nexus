# Nexus: Anomaliyle Tetiklenen Aktif Savunma

Tarih: 2026-11-06. Durum: onaylandı.

## Amaç

Nexus bir tez projesi ve tezin başlığı "Real-time Anomaly Detection & Active Defense". Bugün iki parça da var ama birbirine bağlı değil: bloklar sabit kurallardan geliyor, ML yalnızca alarm üretiyor. Kullanıcı başlığın gerçekten doğru olmasını, sistemin gerçek bir sunucuda kullanılabilmesini ve en az %95 başarıyla tespit edip bloklamasını istiyor.

Hedef: Anomali modeli blok kararının gerçek bir parçası olsun. Kuralların eşiğinin altında kalan saldırıları da yakalasın, gerçek müşterileri bloklamasın ve sonuçlar jüriye savunulabilir biçimde ölçülsün.

**En üst kural değişmiyor: Müşteriyi engellememek, saldırı kaçırmaktan önemlidir. Şüphede kalınırsa engellenmez.**

## Başarı ölçütü

Kullanıcının "%95 doğruluk" hedefi şöyle ölçülür. Bölme önerisi Claude'un kararıdır, çünkü düz accuracy dengesiz veride anlamsızdır: hiçbir şeyi bloklamayan sistem bile %99 accuracy alabilir.

| Ölçü | Hedef | Birim |
|---|---|---|
| Recall | En az %95 | Saldırgan IP'ler, saldırı sınıfı başına ayrı ayrı |
| Blok precision | En az %99 | Bloklanan IP'ler |

Her sonuç %95 güven aralığıyla (Wilson) ve örnek sayısıyla raporlanır. Hedef bir vaat değil, ölçülecek bir şeydir. Tutmayan sınıf gizlenmez, olduğu gibi yazılır.

## Sunucudan öğrenilenler

Gerçek bir üretim sunucusunda 2026-11-06'da salt okunur ölçüldü (son 7 gün):

- **SSH:** Log 2026-10-25'e kadar gidiyor. 4354 geçersiz kullanıcı denemesi, 488 farklı IP, 143 başarılı giriş. Gerçek IP görünüyor. "Failed" satırı yok.
- **fail2ban:** `sshd` jail'i açık, toplam 319 ban.
- **Web hacmi:** Günde yaklaşık 580 istek. Docker logları 10 MB'da dönüyor, Caddy access log'u kapalı.
- **Web IP'si:** nginx logunun ilk alanı hep Caddy'nin iç IP'si. Gerçek IP yalnızca son alanda.
- **Web taraması:** Yaklaşık 348 tarama izi var ama toplam 7 tane 4xx dönmüş. Uygulama taramalara çoğunlukla 200 dönüyor, bu yüzden 4xx arayan `web_probe` kuralı bunları kaçırır. Sayım tüm satırda arandı, kesin değil.
- **Cloudflare:** Sitelerden biri yalnızca Cloudflare'den trafik kabul ediyor. Bu trafikte firewall gerçek IP'yi göremez. Diğer site notlara göre Cloudflare arkasında değil.

Sonuçlar:

1. SSH verisi gerçek ve bol. Web verisi az, gerçek müşteri davranışı için ek kaynak gerekir.
2. Bu sunucuda saldırganlar azınlık değil. "Nadir olan anormaldir" varsayımı burada tutmaz, bu da model seçimini belirler.

## Hedefler

- IP başına davranış skoru üreten, agent üzerinde çalışan bir anomali modeli.
- Model skoru ile log kanıtını birleştiren blok kararı.
- Caddy JSON loglarından gerçek istemci IP'si okuma.
- Ham logları mevcut kural motorundan geçiren çevrimdışı replay aracı.
- fail2ban, yalnızca kurallar, yalnızca model ve kurallar + model için aynı veride karşılaştırma.

## Hedef olmayanlar

- Cloudflare API ile bloklama. Cloudflare arkasındaki web trafiği bu sürümde bloklanmaz, alarm üretir. Web bloğu doğrudan gelen trafikte gösterilir.
- Sunucu metriklerindeki ensemble'ı blok kararına bağlamak. Metrikler IP söylemediği için alarm olarak kalır.
- Her istekte farklı IP kullanan dağıtık saldırıları yakalamak. IP başına kanıt oluşmaz, kapsam dışı olarak yazılır.
- Agent üzerinde model eğitimi.

## Yapılmaması gerekenler

Şunlar teknik olarak çalışsa bile başarısızlık sayılır:

- Model skorunun tek başına birini bloklaması.
- Central'ın agent'a blok isteği ya da model gönderebilmesi. `SECURITY.md`'deki garanti korunur.
- Agent'a numpy, scikit-learn ya da torch eklemek. Agent Python 3.9+ üzerinde `psutil` ve `requests` ile çalışır.
- `X-Forwarded-For`'u saldırganın yazabileceği bir alandan okumak.
- Simüle veriyle %95 gösterip bunu gerçek sunucu sonucu gibi sunmak.
- Tuning için kullanılan veriyle raporlamak.

## Yaklaşımlar

| | Yaklaşım | Artı | Eksi |
|---|---|---|---|
| **A (seçilen)** | IP bazlı model + kanıt kapısı | Başlık doğru olur, kural altı saldırıyı yakalar, garantiler korunur | En çok iş bu |
| B | Yalnızca model bloklar | Başlığa en düz uyan | Skor yanılınca müşteri bloklanır, %99 precision beklenmez |
| C | Sunucu modeli eşikleri sıkılaştırır | En az kod | Saldırganı model seçmiyor, jüride zayıf |

Kullanıcı seçimi Claude'a bıraktı ("hangisi en iyisiyse"), A seçildi. B, karşılaştırma için çevrimdışı ölçülür, hiçbir zaman bloklamaz.

## Tasarım

### Akış

```
Log satırı -> mevcut parser -> LogEvent
                                  |-> mevcut kurallar ----------------------> blok
                                  |-> IP penceresi -> kanıt kapısı -> model -> blok
                                                                            -> Watch / alarm
```

Mevcut kurallar aynen çalışmaya devam eder. Model onların yanına ek bir yol olarak gelir, onları değiştirmez.

### IP özellikleri

Agent, kanal başına ayrı olarak her IP için kayan pencere tutar (web ve SSH ayrı model). Başlangıç özellikleri:

- **Web:** istek sayısı, tepe hız, farklı path sayısı ve oranı, 4xx ve 5xx oranı, statik dosya oranı, durum kodundan bağımsız tarama izi sayısı, exploit kalıbı sayısı, login path sayısı, boş user agent, istek aralıklarının düzenliliği.
- **SSH:** deneme sayısı, geçersiz kullanıcı sayısı, farklı kullanıcı adı sayısı, deneme aralıklarının düzenliliği.

Pencere belleği mevcut `max_tracked_ips` sınırına uyar. Ham satır tutulmaz, sayaç tutulur.

### Model

Tek bir küresel model. Agent paketiyle birlikte gelir (`nexus_agent/data/`), güncellemesi agent sürümüyle olur.

- **Yöntem:** Yalnızca meşru davranışla eğitilen novelty detection. Saldırganlar çoğunlukta olduğu için tüm trafikle eğitmek saldırganı "normal" öğretir. Eğitim yalnızca kanıt kapısını geçen müşteri satırlarıyla yapılır, çünkü model yalnızca orada sorulur.
- **Aday:** Önce Isolation Forest, ağaçları JSON'a aktarılıp agent'ta saf Python ile skorlanır. ECOD de ölçülür. Ölçümde hangisi iyiyse o kalır.
- **Eşik:** Eğitimde etiketli doğrulama verisinden, blok precision hedefine göre sabitlenir. Sunucu başına kalibrasyon yok, çünkü yerel trafik saldırgan ağırlıklıdır ve eşiği yukarı iter.

Sunucu metrik ensemble'ında bu sorun çıkmıştı: sabit tek eşik batch sunucuda %11 yanlış alarm verdi. IP özellikleri trafik hacminden daha az etkilenir, ama bu varsayım ölçümde sunucu başına ayrı kontrol edilir.

### Kanıt kapısı

Blok için hepsi gerekir:

1. Mod `enforce` ve `NEXUS_RULE_ANOMALY_BLOCK=1`. Bu ayar varsayılan olarak kapalıdır, kapalıyken yalnızca alarm üretilir. Gölge mod için ayar açılır, mod `observe` kalır: kararlar Watch'ta görünür, kimse bloklanmaz.
2. Pencerede en az 3 el sıkışmayla kanıtlı şüpheli olay: geçersiz kullanıcı veya başarısız giriş, durum kodundan bağımsız tarama izi, exploit kalıbı, login path'inde 401 veya 403. Log satırı bağlantının tamamlandığını gösterir, kapalı port SYN'i kanıt sayılmaz.
3. Model skoru eşiğin üstünde.
4. Mevcut korumaların hiçbiri geçerli değil: `Protector.reason`, `is_shared`, doğrulanmış bot, CDN arkası. Bunlardan biri varsa blok yok; CDN ve paylaşımlı adreste alarm üretilir.

Model yalnızca 2. maddeyi geçen IP'ler için çalışır, böylece normal ziyaretçi CPU harcatmaz.

### Tepki

Yeni kurallar: `anomaly_ssh` ve `anomaly_web`.

- Yalnızca saldırılan port bloklanır. Asla `block_all` yok.
- Süre 15 dakika, tekrar eden IP için mevcut iki katına çıkarma ve 24 saat sınırı geçerli.
- Mevcut devre kesici, panel "This is a customer" akışı ve unblock aynen çalışır.
- Panelde ayrı kural adı olarak görünür ve kanıt olarak skor, olay sayısı ve özellikler gösterilir.

### Caddy logu

Yeni okuma biçimi: `NEXUS_WEB_LOG_FORMAT=caddy-json` ve `NEXUS_WEB_LOGS`. IP olarak `request.client_ip` okunur. Caddy bu alanı `trusted_proxies` ayarına göre hesapladığı için istemci sahte değer yazamaz. Bu ayar açıkça açılmadan kullanılmaz, ayarın güvenli olması operatörün sorumluluğu olarak README'ye yazılır.

Bağlantı kaynağı (`request.remote_ip`) `client_ip`'den farklıysa istek bir proxy üzerinden gelmiştir. Firewall istemciyi göremediği için yalnızca alarm üretilir.

### Replay aracı

`scripts/replay.py`, ham log dosyalarını zaman sırasıyla mevcut parser, `RuleEngine` ve yeni yoldan geçirir, gerçek nft çalıştırmaz, karar listesi üretir. fail2ban aynı veride, kendi logundaki ban kayıtlarından ya da aynı `findtime`/`maxretry` ayarıyla karşılaştırılır.

## Veri ve değerlendirme

| Kaynak | Ne için | Etiket |
|---|---|---|
| Gerçek SSH logları (sunucu) | SSH eğitim ve test | Başarılı giriş yapan bilinen admin IP'leri meşru. Hiç başarılı girişi olmayan ve birden fazla geçersiz kullanıcı deneyen IP saldırgan. Arada kalan dışarıda bırakılır ve sayısı raporlanır |
| Gerçek web logları (Caddy) | Müşteriyi bloklamama kanıtı | Tarama izi olmayan oturumlar meşru. Örneklem elle kontrol edilir |
| Mevcut e2e stack'i | Kontrollü müşteri ve saldırı | Senaryo bilindiği için kesin |
| Kontrollü saldırılar, ayrı test sunucusu | Yavaş SSH, tarama, exploit (hydra, nikto, gobuster, sqlmap) | Kaynak IP bizde olduğu için kesin |
| Açık etiketli HTTP verisi (aday: CSIC 2010) | Başkalarının tekrarlayabileceği karşılaştırma | Veri setinin etiketi. Uygunluğu ve lisansı inşa sırasında kontrol edilir |

Kurallar:

- Bölme zamana göre yapılır: eski veri eğitim ve eşik, yeni veri rapor. Rapor verisi eşik ayarında kullanılmaz.
- Kaynaklar ayrı raporlanır, tek bir karışık sayıya indirilmez. Simüle sonuç açıkça "simüle" yazılır.
- Dört sistem aynı veride karşılaştırılır: fail2ban, yalnızca kurallar, yalnızca model, kurallar + model.
- Ek ölçümler: tespit süresi, agent CPU ve RAM'i, gerçek sunucuda günlük yanlış blok.

### Gizlilik

IP adresi kişisel veridir. Ham loglar sunucudan çıkmaz. Dışarı yalnızca özellik satırları ve anahtarlı HMAC ile anonimleştirilmiş IP'ler çıkar, anahtar sunucuda kalır. Tezde gerçek IP yer almaz.

## Yayına alma sırası

Her adım kullanıcı onayı ister, çünkü gerçek sunucuya dokunur:

1. Caddy access log'u aç ve reload et. Siteler canlıdır, önce yedek alınır ve log döndürme ayarlanır.
2. Agent'ı `NEXUS_MAX_MODE=observe` ile kur. Hiçbir şey bloklamaz, veri toplar.
3. Yeterli veri birikince modeli eğit, Watch'ta gölge modda çalıştır.
4. Rapor verisinde hedef tutarsa önce SSH'ta, sonra doğrudan gelen web trafiğinde `enforce`. fail2ban ile çakışma bu adımda kontrol edilir.

Gerçek sunucuda `enforce` ölçütü: gölge modda en az 14 gün boyunca Watch'ta meşru bir adres görünmemesi.

## Riskler

- **Az meşru SSH verisi.** 7 günde 143 başarılı giriş var, kaç farklı kişi ve IP'den geldiği ölçülmedi. Model az örnekten öğrenir. Kontrollü meşru oturumlarla desteklenir, zayıf kalırsa SSH'ta kanıt kapısı daha fazla iş yapar ve bu raporda yazılır.
- **Az gerçek müşteri.** Günde 580 istekle "müşteriyi bloklamıyor" iddiası zayıf kalır. %99 precision'ı istatistiksel olarak göstermek yüzlerce blok gerektirir. Güven aralığı dürüstçe yazılır.
- **Admin kilitlenmesi.** Yeni bir IP'den 3 başarısız deneme yapan admin 15 dakika SSH dışı kalabilir. Bugünkü eşik 10. Replay'de 3 sayısı ölçülür, gerekirse yükseltilir.
- **Model kanıt kapısının altında kalır.** Kapı çok sıkıysa model yeni bir şey yakalamaz, başlık yine zayıflar. Karşılaştırmada "kuralların yakalamadığı ama modelin yakaladığı" sayısı ayrıca raporlanır.
- **Etiket hatası.** SSH etiketleri kurala dayanıyor. Bu sınır tezde belirtilir.
- **Süre.** Gerçek veri takvime bağlıdır, kod ne kadar hızlı biterse bitsin veri toplama süresi kısalmaz.

## İnşa edene kalanlar

Pencere uzunlukları, kesin özellik listesi, ağaç sayısı ve derinliği, replay çıktı biçimi. Bunlar ölçümle seçilir. Claude'un kararları: başarı ölçütünün bölünmesi, yaklaşım A, kanıt kapısında 3 olay, 15 dakika blok, Cloudflare API'nin kapsam dışı olması, 14 günlük gölge mod.
