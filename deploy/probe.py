#!/usr/bin/env python3
import time
import json
import urllib.request
import urllib.error
import os
import subprocess

API_URL = os.getenv("API_URL", "http://localhost:8000/api/ingest")
NODE_ID = os.getenv("NODE_ID", "t3-micro-1")
INTERVAL = int(os.getenv("INTERVAL", "5"))

try:
    import psutil
except ImportError:
    print("Please install psutil: pip install psutil")
    exit(1)

def get_latency():
    """Örnek gecikme ölçümü: 8.8.8.8'e ping atarak ping süresini hesaplar."""
    try:
        start = time.time()
        subprocess.check_output(["ping", "-c", "1", "-W", "1", "8.8.8.8"], stderr=subprocess.STDOUT)
        return (time.time() - start) * 1000.0
    except Exception:
        return 0.0

def main():
    print(f"🚀 Başlıyor: Node = {NODE_ID}")
    print(f"📡 Hedef = {API_URL}")
    print(f"⏱️  Aralık = {INTERVAL} saniye")
    
    # Ağ sayacı başlangıcı
    net_io = psutil.net_io_counters()
    last_bytes_recv = net_io.bytes_recv
    last_time = time.time()
    
    # CPU baseline ayarla
    psutil.cpu_percent(interval=None)
    
    while True:
        time.sleep(INTERVAL)
        now = time.time()
        dt = now - last_time
        
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        
        net_io = psutil.net_io_counters()
        bytes_recv = net_io.bytes_recv
        # bps'den kbps'ye dönüşüm
        net_kbps = ((bytes_recv - last_bytes_recv) * 8) / (dt * 1024)
        
        last_bytes_recv = bytes_recv
        last_time = now
        
        lat = get_latency()
        
        payload = {
            "node_id": NODE_ID,
            "timestamp": now,
            "cpu_pct": round(cpu, 2),
            "memory_pct": round(mem, 2),
            "net_kbps": round(net_kbps, 2),
            "latency_ms": round(lat, 2)
        }
        
        req = urllib.request.Request(API_URL, method="POST")
        req.add_header("Content-Type", "application/json")
        data = json.dumps(payload).encode("utf-8")
        
        try:
            with urllib.request.urlopen(req, data=data, timeout=5) as resp:
                if resp.status == 200:
                    print(f"✅ Gönderildi: CPU:%{payload['cpu_pct']} RAM:%{payload['memory_pct']} NET:{payload['net_kbps']}kbps LAT:{payload['latency_ms']}ms")
                else:
                    print(f"⚠️ Hata: {resp.status}")
        except urllib.error.URLError as e:
            print(f"❌ Bağlantı hatası ({API_URL}): {e.reason}")
        except Exception as e:
            print(f"❌ Hata: {e}")

if __name__ == "__main__":
    main()
