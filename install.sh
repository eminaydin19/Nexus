#!/bin/bash
set -e

echo "=============================================="
echo "    NEXUS AI SECURITY - AWS INSTALLER         "
echo "=============================================="

# 1. Check & Install Docker
if ! command -v docker &> /dev/null; then
    echo "[+] Docker bulunamadı. Kuruluyor..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo "[+] Docker başarıyla kuruldu."
else
    echo "[+] Docker zaten kurulu."
fi

# 2. Check & Install Docker Compose
if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo "[+] Docker Compose bulunamadı. Lütfen paket yöneticinizle kurun (örn: sudo apt install docker-compose-plugin)"
    exit 1
fi

echo ""
echo "=============================================="
echo " AWS CLOUDWATCH BAĞLANTISI (BOTO3) AYARLARI "
echo "=============================================="
echo "Nexus'un AWS CloudWatch'tan gerçek verileri çekebilmesi için"
echo "IAM yetkilerine (CloudWatch Read) sahip bir kullanıcı anahtarı gereklidir."
echo "Eğer bu sunucuda bir IAM Role tanımlıysa, bu alanları boş bırakabilirsiniz."
echo ""

read -p "AWS_ACCESS_KEY_ID (Boş bırakmak için Enter): " AWS_ACCESS_KEY_ID
read -p "AWS_SECRET_ACCESS_KEY (Boş bırakmak için Enter): " AWS_SECRET_ACCESS_KEY
read -p "AWS_REGION [Örn: us-east-1] (Varsayılan: eu-central-1): " AWS_REGION
AWS_REGION=${AWS_REGION:-eu-central-1}

# 3. Create .env file
echo "[+] .env dosyası oluşturuluyor..."

# Generate a random API key for the ingest endpoint
RANDOM_API_KEY=$(openssl rand -hex 16)

cat <<EOF > .env
# --- NEXUS AYARLARI ---
HTTP_BIND=80
INGEST_API_KEY=$RANDOM_API_KEY
INGESTION_SOURCE=cloudwatch

# --- AWS CLOUDWATCH AYARLARI ---
AWS_REGION=$AWS_REGION
EOF

if [ -n "$AWS_ACCESS_KEY_ID" ]; then
    echo "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID" >> .env
    echo "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY" >> .env
fi

echo "[+] .env başarıyla oluşturuldu."
echo ""
echo "[+] Nexus sunucusu Docker üzerinden başlatılıyor..."

# Start the docker containers
if docker compose version &> /dev/null; then
    docker compose up -d --build
else
    docker-compose up -d --build
fi

echo ""
echo "=============================================="
echo " KURULUM TAMAMLANDI! 🚀 "
echo "=============================================="
echo "- Arayüze erişmek için tarayıcıda sunucunun IP adresine gidin: http://$(curl -s ifconfig.me)"
echo "- Sistem sadece gerçek AWS CloudWatch verilerini kullanacak şekilde ayarlandı."
echo "- Güvenlik API Anahtarı (Agent'lar için): $RANDOM_API_KEY"
echo "=============================================="
